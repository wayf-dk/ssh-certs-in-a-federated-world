package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

type (
	bucket struct {
		Claims [2]map[string]string
		Ttl    [2]time.Time
		Mutex  sync.RWMutex
	}
)

var (
	//go:embed www
	www embed.FS

	//go:embed assets/ca.template
	caTemplate string

	//go:embed assets/ca.key
	privateKey []byte

	eppnRegexp  = regexp.MustCompile(`[^-a-zA-Z0-9]`)
	tokenRegexp = regexp.MustCompile(`[0-9a-f]+`)
	tmpl        *template.Template

	done chan bool
	//	claims = &bucket{}
	claims = &rendezvous{channels: map[string](chan string){}, xtras: map[string]string{}}
)

func main() {
	go sshserver()
	ca()
}

func ca() {
	tmpl = template.Must(template.New("ca.template").Parse(caTemplate))

	const listenOn = "127.0.0.1:7788"

	fs := http.FileServer(http.FS(www))

	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/www/", fs.ServeHTTP)
	httpMux.Handle("/favicon.ico", http.NotFoundHandler())
	httpMux.HandleFunc("/feedback/", feedbackHandler)
	httpMux.HandleFunc("/", caHandler)

	fmt.Println("Listening on port: " + listenOn)
	err := http.ListenAndServe(listenOn, httpMux)
	fmt.Println("err: ", err)
}

func caHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	v := r.Form

	host := r.Header["X-Forwarded-Host"][0]

	showForm := (host == "sshsp.lan" || v.Get("idplist") == "") && !v.Has("SAMLResponse")

	if showForm {
		tmpl.Execute(w, nil)
		return
	}

	certs := []string{"MIIC7TCCAdWgAwIBAgIBBzANBgkqhkiG9w0BAQsFADAwMQswCQYDVQQGEwJESzENMAsGA1UEChMEV0FZRjESMBAGA1UEAxMJd2F5Zi4yMDE2MB4XDTE1MDEwMTAwMDAwMFoXDTI1MTIzMTAwMDAwMFowMDELMAkGA1UEBhMCREsxDTALBgNVBAoTBFdBWUYxEjAQBgNVBAMTCXdheWYuMjAxNjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOeCt61E+O909jreVUV1tFHQe9m3h612W38OauWftVVrwH0CJpYCFGAMUBcDFkPgocA+XpB2qadF+/dnErIDbTVgxqyewB0TOWmMoqMknrkmS0x0AiRHIBtkzIWFam+EwGtFGA5Hw3sjGPoDXg4cGT731uoCktsH5ELt+eFDXSBOUgxyKzZf8NTXRbLksIdPxNgZ04e5JawFo1cnYbTVYQcleMqOYY3rIDXxA8BTm4ZYCNkxLO0v7YK7+mfF5T1Q5C7FXivoQI+A2mi/qGlwLt+oD81jdYki/v7ApXZi0sdcRovA9H4yFCv4tT5f/Plu8YJ8aXSGpJ8gATPtkY9ul9cCAwEAAaMSMBAwDgYDVR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4IBAQCaDrkKvC9mc8cOmjFhPd/4UgZxol7K0U7GwBY92MXzdE/o4Dd+u3Dw0+O3UsK2kxExFlT3qXuG9XF987xUoGBy+Ip6A14nmKfW9a1hLS7zZoTVpxHebmms8n5voKLPBWowiMwb8jLdVaPzAx7bMnOfXrV3g0L8inPsqgYOgqku9//8I7YnV/r8z0V0uLgi2n9eYDyqvktsL37tIw6RTX/l9J8KQlHy0eWMs9CXDaK1gYdif1EsaHW4xLpjZsohIoovXMtQNTN+jIybXdEDScdLzwT9j9+BU9uHJRx3f3bfwX9QINsDkafDOtBNAnW762LHylOBiXgV2s954JAVY3O+"}
	saml2jwt := "https://wayf.wayf.dk/saml2jwt"
	jwtSP := "http://ssh-ca.deic.dk"
	jwtACS := "https://" + host

	v.Set("acs", jwtACS)
	v.Set("issuer", jwtSP)

	attrs, err := SAML2jwt(w, saml2jwt, v, certs)
	if err != nil {
		log.Panic(err)
	}

	if attrs == nil {
		return
	}

	principal := attrs["eduPersonPrincipalName"].([]interface{})[0].(string)
	data, err := json.Marshal(attrs)

	token := claims.put(string(data))
	principal = eppnRegexp.ReplaceAllString(principal, "_")

	err = tmpl.Execute(w, map[string]any{"token": token, "principal": template.JS(principal)})
	return
}

func feedbackHandler(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/feedback/")
	resp := claims.wait(token)
	io.WriteString(w, resp)
}

func SAML2jwt(w http.ResponseWriter, service string, v url.Values, certificates []string) (res map[string]interface{}, err error) {
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: false}},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	body := strings.NewReader(v.Encode())
	req, _ := http.NewRequest("POST", service, body)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	//	req.Header.Add("Cookie", "wayfid=wayf-qa")
	resp, err := client.Do(req)
	if err != nil {
		return
	}

	if v["SAMLResponse"] == nil { // ask for a SAMLRequest
		for header, val := range resp.Header {
			w.Header().Add(header, val[0]) // Add SAM2jwt headers to our own
		}
		w.WriteHeader(302)
	} else {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		resp.Body.Close()

		payload, err := jwtVerify(string(body), certificates)
		if err != nil {
			return nil, err
		}
		var attrs map[string]interface{}
		err = json.Unmarshal(payload, &attrs)
		if err != nil {
			return nil, err
		}
		return attrs, nil
	}
	return
}

func jwtVerify(jwt string, certificates []string) (payload []byte, err error) {
	if len(certificates) == 0 {
		return payload, errors.New("No Certs found")
	}

	hps := strings.SplitN(jwt, ".", 3)
	hp := []byte(strings.Join(hps[:2], "."))
	headerJSON, _ := base64.RawURLEncoding.DecodeString(hps[0])

	header := struct{ Alg string }{}
	err = json.Unmarshal(headerJSON, &header)
	if err != nil {
		return
	}
	var hh crypto.Hash
	var digest []byte
	switch header.Alg {
	case "RS256":
		dg := sha256.Sum256(hp)
		digest = dg[:]
		hh = crypto.SHA256
	case "RS512":
		dg := sha512.Sum512(hp)
		digest = dg[:]
		hh = crypto.SHA512
	default:
		return payload, fmt.Errorf("Unsupported alg: %s", header.Alg)
	}

	sign, _ := base64.RawURLEncoding.DecodeString(hps[2])
	var pub *rsa.PublicKey
	for _, certificate := range certificates {
		pub, err = cert2publicKey(certificate)
		if err != nil {
			return payload, err
		}
		err = rsa.VerifyPKCS1v15(pub, hh, digest, sign)
		if err == nil {
			payload, err := base64.RawURLEncoding.DecodeString(hps[1])
			return payload, err
		}
	}
	return
}

func cert2publicKey(cert string) (publickey *rsa.PublicKey, err error) {
	key, err := base64.StdEncoding.DecodeString(cert)
	if err != nil {
		return
	}
	pk, err := x509.ParseCertificate(key)
	if err != nil {
		return
	}
	publickey = pk.PublicKey.(*rsa.PublicKey)
	return
}

var clientPubKey ssh.PublicKey

func sshserver() {
	// An SSH server is represented by a ServerConfig, which holds
	// certificate details and handles authentication of ServerConns.
	config := &ssh.ServerConfig{
		// Remove to disable public key auth.
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			clientPubKey = pubKey
			return nil, nil
		},
	}

	private, err := ssh.ParsePrivateKey(privateKey)
	if err != nil {
		log.Fatal("Failed to parse private key: ", err)
	}

	config.AddHostKey(private)

	// Once a ServerConfig has been configured, connections can be
	// accepted.
	listener, err := net.Listen("tcp", "0.0.0.0:2022")
	if err != nil {
		log.Fatal("failed to listen for connection: ", err)
	}
	fmt.Println("listening on 2022")

	for {
		nConn, err := listener.Accept()
		if err != nil {
			log.Fatal("failed to accept incoming connection: ", err)
		}

		// Before use, a handshake must be performed on the incoming
		// net.Conn.
		conn, chans, reqs, err := ssh.NewServerConn(nConn, config)
		if err != nil {
			log.Fatal("failed to handshake: ", err)
		}

		// The incoming Request channel must be serviced.
		go ssh.DiscardRequests(reqs)

		for newChannel := range chans {
			if newChannel.ChannelType() != "session" {
				newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
				continue
			}

			channel, reqs, err := newChannel.Accept()
			if err != nil {
				log.Fatalf("Could not accept channel: %v", err)
			}

			var token string
		reqLoop:
			for req := range reqs {
				fmt.Println(req)
				switch req.Type {
				case "shell":
					break reqLoop
				case "exec":
					token = tokenRegexp.FindString(string(req.Payload[4:])) // string with 32 bits length prefix
					fmt.Println(token)
					if data, ok := claims.get(token); ok {
						cert := newCertificate(data)
						s, _ := json.MarshalIndent(cert, "", "    ")
						claims.meet(token, string(s))
						certTxt := string(ssh.MarshalAuthorizedKey(cert))
						io.WriteString(channel, fmt.Sprintf("%s", certTxt))
					}
					break reqLoop
				}
			}
			if token == "" {
				buf := make([]byte, 1024)
				channel.Read(buf)
				token = string(tokenRegexp.Find(buf))

				if data, ok := claims.get(token); ok {
					cert := newCertificate(data)
					s, _ := json.MarshalIndent(cert, "", "    ")
					claims.meet(token, string(s))
					certTxt := string(ssh.MarshalAuthorizedKey(cert))
					io.WriteString(channel, fmt.Sprintf("%s", certTxt))
				}
			}
			channel.Close()
		}
		conn.Close()
		fmt.Println("out of loop")
	}
}

func newCertificate(data string) (cert *ssh.Certificate) {
	attrs := map[string]any{}
	err := json.Unmarshal([]byte(data), &attrs)
	if err != nil {
		log.Panic(err)
	}
	principal := eppnRegexp.ReplaceAllString(attrs["eduPersonPrincipalName"].([]interface{})[0].(string), "_")
	cert = &ssh.Certificate{
		CertType: ssh.UserCert,
		Key:      clientPubKey,
		Permissions: ssh.Permissions{
			CriticalOptions: map[string]string{}, // "force-command": "id ; pwd ; /usr/bin/ls -a"},
			Extensions:      map[string]string{"permit-agent-forwarding": "", "permit-pty": "", "groups@wayf.dk": string(data)},
		},
		KeyId:           principal,
		ValidPrincipals: []string{principal, "sshfedlogin", "sshweblogin"},
		ValidAfter:      uint64(time.Now().Unix() - 60),
		ValidBefore:     uint64(time.Now().Unix() + 36*3600),
	}
	signer, err := ssh.ParsePrivateKey(privateKey)
	if err != nil {
		log.Fatal(err)
	}
	err = cert.SignCert(rand.Reader, signer)
	if err != nil {
		log.Fatal(err)
	}
	return
}

func (s *bucket) put(v string) (k string) {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()
	k = nonce()
	s.update()
	s.Claims[1][k] = v
	return
}

func (s *bucket) get(k string) (v string, ok bool) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	s.update()
	for i, _ := range "01" {
		if v, ok = s.Claims[i][k]; ok {
			delete(s.Claims[i], k) // no-ops if nothing there ...
			return
		}
	}
	return
}

func (s *bucket) update() {
	const ttl = time.Second * 30
	for _, _ = range "01" {
		if s.Ttl[0].Before(time.Now()) {
			s.Claims[0], s.Claims[1] = s.Claims[1], map[string]string{}
			s.Ttl[0], s.Ttl[1] = s.Ttl[1], time.Now().Add(ttl)
		} else {
			return // if 1st bucket is ok no need to check the last
		}
	}
}

func nonce() (s string) {
	b := make([]byte, 8) // 64 bits
	_, err := rand.Read(b)
	if err != nil {
		log.Panic("Problem with making random number:", err)
	}
	b[0] = b[0] & byte(0x7f) // make sure it is a positive 64 bit number
	return hex.EncodeToString(b)
}

// PP - super simple Pretty Print - using JSON
func PP(i ...interface{}) {
	for _, e := range i {
		s, _ := json.MarshalIndent(e, "", "    ")
		log.Println(string(s))
	}
	return
}

// rendezvous

type (
	rendezvous struct {
		mx       sync.RWMutex
		channels map[string](chan string)
		xtras    map[string]string
	}
)

func (rv *rendezvous) put(xtra string) (token string) {
	token = nonce()
	c := make(chan string, 1)
	rv.mx.Lock()
	rv.channels[token] = c
	rv.xtras[token] = xtra
	rv.mx.Unlock()
	return
}

func (rv *rendezvous) get(token string) (xtra string, ok bool) {
	rv.mx.RLock()
	xtra, ok = rv.xtras[token]
	rv.mx.RUnlock()
	return
}

func (rv *rendezvous) meet(token, data string) {
	rv.mx.RLock()
	defer rv.mx.RUnlock()
	rv.channels[token] <- data
}

func (rv *rendezvous) wait(token string) (data string) {
	rv.mx.RLock()
	c, ok := rv.channels[token]
	rv.mx.RUnlock()
	data = "NOT"
	if ok {
		select {
		case data = <-c:
		case <-time.After(30 * time.Second):
		}
	}
	rv.mx.Lock()
	defer rv.mx.Unlock()
	delete(rv.channels, token)
	delete(rv.xtras, token)
	return
}

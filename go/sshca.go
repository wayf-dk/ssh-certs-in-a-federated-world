package main

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
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
	principal := r.Header.Get("Oidc_claim_edupersonprincipalname")
	if principal == "" { // show mindthegap
		tmpl.Execute(w, nil)
		return
	}
	principal = eppnRegexp.ReplaceAllString(principal, "_")
	schacHomeOrganization := template.JS(r.Header.Get("Oidc_claim_schacHomeOrganization"))
	token := claims.put(principal)
	PP("home", schacHomeOrganization)
	tmpl.Execute(w, map[string]any{"token": token, "principal": template.JS(principal), "schacHomeOrganization": schacHomeOrganization})
	return
}

func feedbackHandler(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/feedback/")
	resp := claims.wait(token)
	cert := map[string]any{}
	// for now we ignore the error that parts of the Key field kan be far longer than an float64 - that is the format all json numbers is unmarshaled in to
	json.Unmarshal([]byte(resp), &cert)
    if _, ok := cert["KeyId"]; ok {
        const iso = "2006-01-02T15:04:05"
        va := time.Unix(int64(cert["ValidAfter"].(float64)), 0).Format(iso)
        vb := time.Unix(int64(cert["ValidBefore"].(float64)), 0).Format(iso)
        hours := cert["ValidBefore"].(float64) - cert["ValidAfter"].(float64)
        resp = fmt.Sprintf("Valid %.0f hours from %s to %s\n\n%s", hours/3600, va, vb, resp)
	}
    io.WriteString(w, resp)
}

var clientPubKey ssh.PublicKey

func sshserver() {
	// An SSH server is represented by a ServerConfig, which holds
	// certificate details and handles authentication of ServerConns.
	config := &ssh.ServerConfig{
		// Remove to disable public key auth.
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
            if _, ok := pubKey.(*ssh.Certificate); ok {
                pubKey = pubKey.(*ssh.Certificate).Key
            }
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
	principal := data
	cert = &ssh.Certificate{
		CertType: ssh.UserCert,
		Key:      clientPubKey,
		Permissions: ssh.Permissions{
			CriticalOptions: map[string]string{}, // "force-command": "id ; pwd ; /usr/bin/ls -a"},
			Extensions:      map[string]string{"permit-agent-forwarding": "", "permit-pty": ""},
		},
		KeyId:           principal,
		ValidPrincipals: []string{principal, "cert-tester"},
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

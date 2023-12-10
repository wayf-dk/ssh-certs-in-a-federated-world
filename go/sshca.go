package main

import (
	"crypto/rand"
	"embed"
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
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

type (
    provisioner struct {
        ConfigurationEndpoint string `json:"configurationEndpoint"`
    }

    opconfig struct {
        Userinfo string `json:"userinfo_endpoint"`
        Device_authorization string `json:"device_authorization_endpoint"`
        Token string `json:"token_endpoint"`
    }

    sessionInfo struct {
        user string
        publicKey ssh.PublicKey
    }
)

const (
    MyAccessIDAcc = "MyAccessIDAcc"
    clientID = "APP-69C9BE38-B37C-429F-8C8F-4E20CF99BCA6"
    verification_uri_template = "https://sshca.deic.dk/%s\n"
    MyAccessIDTTL = 15*60
    SSHCATTL = 36*3600
)

var (
	//go:embed www
	www embed.FS

	//go:embed assets/ca.template
	caTemplate string

	//go:embed assets/ca.key
	privateKey []byte

	eppnRegexp  = regexp.MustCompile(`[^-a-zA-Z0-9]`)
	tmpl        *template.Template

	done chan bool
	claims = &rendezvous{channels: map[string](chan string){}, xtras: map[string]string{}}
	publicKeys = &publicKeyMap{keys: map[string]ssh.PublicKey{}}
    op = opconfig{}
    client = &http.Client{}
)

func main() {
    provisioners, _ := www.ReadFile("www/provisioners.json")
    config := map[string][]provisioner{}
	json.Unmarshal([]byte(provisioners), &config)
    configEndpoint := config["provisioners"][0].ConfigurationEndpoint
    resp, _ := http.Get(configEndpoint)
    configJson, _ := io.ReadAll(resp.Body)
	json.Unmarshal(configJson, &op)
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
	httpMux.HandleFunc("/ssh/sign", sshsignHandler)
	httpMux.HandleFunc("/", caHandler)

	fmt.Println("Listening on port: " + listenOn)
	err := http.ListenAndServe(listenOn, httpMux)
	fmt.Println("err: ", err)
}

func caHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	principal := r.Header.Get("Oidc_claim_edupersonprincipalname")
    PP("principal", principal, r.Method, r.Form)
	if principal == "" { // show mindthegap
	    path := append(strings.SplitN(r.URL.Path, "/", 3)[1:], "") // starts with / and idp might be empty
	    if path[0] == "d" {
            token := claims.put("")
        	claims.set(token+"_zzz", "")
            resp := device_authorization_request()
		    tmpl.Execute(w, map[string]string{"state": token, "verification_uri": resp["verification_uri_complete"].(string)})
		    go func(token string) {
                resp, err := token_request(resp["device_code"].(string))
                if resp != nil {
                    PP("device_code error", token, resp, err)
                    resp, err = post2(resp["access_token"].(string), op.Userinfo)
                    if err != nil {
                        return
                    }
                    s, _ := json.Marshal(resp)
                    PP("user info", resp)
                    claims.meet(token, string(s))
                }
            }(token)
	        return
	    }
	    PP("path", path, r.URL.Path)
	    token := path[0]+r.Form.Get("token")
	    idp, _ := claims.get(token)
	    idp = idp+path[1]+r.Form.Get("idpentityid")
	    if idp == "" {
		    tmpl.Execute(w, map[string]string{"token": token})
		    return
	    } else {
            if token == "" {
                token = claims.put("")
            }
    		data := url.Values{}
    		data.Set("state", token)
    		data.Set("idpentityid", idp)
            http.Redirect(w, r, "/ca/?"+data.Encode(), http.StatusFound)
    	    return
	    }
	}
	principal = eppnRegexp.ReplaceAllString(principal, "_")

	data := map[string][]string{}
	for claim, claims := range r.Header {
	    if strings.HasPrefix(claim, "Oidc_claim_") {
	        data[claim[11:]] = claims
	    }
	}
	state := r.Form.Get("state") // when returning
	fmt.Println("state", state)
    s, _ := json.Marshal(data)
	claims.meet(state, string(s))
	claims.set(state+"_zzz", "")
	tmpl.Execute(w, map[string]any{"state": state})
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

func sshsignHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	r.ParseForm()
    req, _ := io.ReadAll(r.Body)
	params := map[string]string{}
  	err := json.Unmarshal(req, &params)
  	fmt.Println(err, params)
  	publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(params["PublicKey"]))
	resp, err := post2(params["OTT"], op.Userinfo)
	if err != nil {
	    return
	}
    sshCertificate := newCertificate(publicKey, resp, MyAccessIDTTL)
    res := ssh.MarshalAuthorizedKey(sshCertificate)
    w.Write(res)
    return
}

func sshserver() {
    allowedKeyTypes := map[string]bool{
        "ssh-ed25519": true,
        "ssh-ed25519-cert-v01@openssh.com": true,
    }
	config := &ssh.ServerConfig{
		// Remove to disable public key auth.
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
		    fmt.Println("pubkey type", pubKey.Type(), c.User())
		    if !allowedKeyTypes[pubKey.Type()] {
		        return nil, errors.New("xxx")
		    }
            publicKeys.set(string(c.SessionID()), sessionInfo{c.User(), pubKey})
			return nil, nil // errors.New("xxx")
		},
	}
	private, err := ssh.ParsePrivateKey(privateKey)
	if err != nil {
		log.Fatal("Failed to parse private key: ", err)
	}

	config.AddHostKey(private)

	// Once a ServerConfig has been configured, connections can be
	// accepted.
	const listenOn = "0.0.0.0:22"
	listener, err := net.Listen("tcp", listenOn)
	if err != nil {
		log.Fatal("failed to listen for connection: ", err)
	}
	fmt.Println("listening on " + listenOn)

	for {
		nConn, err := listener.Accept()
		if err != nil {
			log.Println("failed to accept incoming connection: ", err)
			continue;
		}
        go handleSSHConnection(nConn, config)
	}
}

func handleSSHConnection(nConn net.Conn, config *ssh.ServerConfig) {
	// An SSH server is represented by a ServerConfig, which holds
	// certificate details and handles authentication of ServerConns.
    // Before use, a handshake must be performed on the incoming
    // net.Conn.
    type tokenType uint8
    const (
        normal tokenType = iota
        device
    )

    conn, chans, reqs, err := ssh.NewServerConn(nConn, config)
    if err != nil {
        log.Println("failed to handshake: ", err)
        return
    }

    // The incoming Request channel must be serviced.
    go ssh.DiscardRequests(reqs)

    for newChannel := range chans {
        if newChannel.ChannelType() != "session" {
            newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
            return
        }

        channel, reqs, err := newChannel.Accept()
        if err != nil {
            log.Println("Could not accept channel: %v", err)
        }

        for req := range reqs {
            fmt.Println("reqs", req)
            switch req.Type {
            case "exec":
                var tt tokenType
                p := append(strings.Split(string(req.Payload[4:]), " "), "")
                token, idp := p[0], p[1]
                fmt.Println(token)
                if token == "t" {
                    token = claims.put(idp)
                    fmt.Println("t", verification_uri_template, token)
                    io.WriteString(channel, fmt.Sprintf(verification_uri_template, token))
                } else if token == "d" {
                    tt = device
                    resp := device_authorization_request()
                    verification_uri_complete := resp["verification_uri_complete"].(string)
                    qr, err := exec.Command(`/usr/bin/qrencode`, `-tUTF8`, verification_uri_complete).CombinedOutput()
                    fmt.Println(err, string(qr))
                    io.WriteString(channel, fmt.Sprintf("%s%s\n#\n", qr, verification_uri_complete ))
                    resp, err = token_request(resp["device_code"].(string))
                    PP("device_code error", resp, err)
                    if resp == nil {
                        break
                    }
	                resp, err = post2(resp["access_token"].(string), op.Userinfo)
	                if err != nil {
	                    break
	                }
                    s, _ := json.Marshal(resp)
                    PP("user info", resp)
                    token = claims.put("")
                    claims.meet(token, string(s))
                }
                fmt.Println(token)
                data := claims.wait(token)
                si, ok := publicKeys.get(string(conn.SessionID()))
                if ok && data != "NOT" {
                    res := map[string]any{}
                  	json.Unmarshal([]byte(data), &res)
                    cert := newCertificate(si.publicKey, res, SSHCATTL)
                    s, _ := json.MarshalIndent(cert, "", "    ")
                    PP("cert", s)
                    if tt != device {
                        claims.meet(token+"_zzz", string(s))
                    }
                    certTxt := ssh.MarshalAuthorizedKey(cert)
                    keyName := si.publicKey.Type()[4:]
                    io.WriteString(channel, fmt.Sprintf("%s%s\n", certTxt, keyName)) // certTxt already have a linefeed at the end ..
                }
                channel.Close()
            default:
                if req.WantReply {
                    req.Reply(false, nil)
                }
            }
        }
        channel.Close()
    }
    conn.Close()
    fmt.Println("out of loop")
}

func newCertificate(pubkey ssh.PublicKey, claims map[string]any, ttl int64) (cert *ssh.Certificate) {
    if _, ok := pubkey.(*ssh.Certificate); ok {
        pubkey = pubkey.(*ssh.Certificate).Key
    }
  	PP("claims", claims)
    var principal string
    val, ok := claims["edupersonprincipalname"].([]any)
    PP("principal ...", val, ok)
    if val, ok := claims["edupersonprincipalname"].([]any); ok {
        principal = val[0].(string)
    } else if val, ok :=  claims["sub"].(string); ok {
        principal = val
    } else {
        fmt.Println("returning ...");
        return nil
    }
    PP("principal", principal)
	// principal = eppnRegexp.ReplaceAllString(principal, "_")

    now := time.Now().In(time.FixedZone("UTC", 0)).Unix()
	cert = &ssh.Certificate{
		CertType: ssh.UserCert,
		Key:      pubkey,
		Permissions: ssh.Permissions{
			CriticalOptions: map[string]string{}, // "force-command": "id ; pwd ; /usr/bin/ls -a"},
			Extensions:      map[string]string{"permit-agent-forwarding": "", "permit-pty": ""},
			// Extensions:      map[string]string{"permit-agent-forwarding": "", "permit-pty": "", "groups@wayf.dk": data},
		},
		KeyId:           principal,
		ValidPrincipals: []string{principal, "cert-tester"},
		ValidAfter:      uint64(now - 60),
		ValidBefore:     uint64(now + ttl),
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
	b := make([]byte, 5) // 64 bits
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
		switch v := e.(type) {
		case []byte:
			fmt.Println(string(v))
		default:
			s, _ := json.MarshalIndent(v, "", "    ")
			fmt.Println(string(s))
		}
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

func (rv *rendezvous) set(token, xtra string) {
	c := make(chan string, 1)
	rv.mx.Lock()
	rv.channels[token] = c
	rv.xtras[token] = xtra
	rv.mx.Unlock()
	return
}

func (rv *rendezvous) put(xtra string) (token string) {
	token = nonce()
	rv.set(token, xtra)
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

// pubkeys

type (
	publicKeyMap struct {
		info map[string]sessionInfo
		mx  sync.RWMutex
	}
)

func (pk *publicKeyMap) set(k string, v sessionInfo) {
	pk.mx.Lock()
	defer pk.mx.Unlock()
	pk.info[k] = v
}

func (pk *publicKeyMap) get(k string) (v sessionInfo, ok bool) {
	pk.mx.Lock()
	defer pk.mx.Unlock()
	v, ok = pk.info[k]
	delete(pk.info, k)
	return
}

// Device flow

func device_authorization_request() (res map[string]any) {
    v := url.Values{}
    v.Set("client_id", clientID)
    v.Set("scope",  "openid email profile eduperson_entitlement")
    resp, _ := client.PostForm(op.Device_authorization, v)
    responsebody, _ := ioutil.ReadAll(resp.Body)
    res = map[string]any{}
    json.Unmarshal(responsebody, &res)
    PP("resp", res)
    return res
}

func token_request(device_code string) (res map[string]any, err error) {
    v := url.Values{}
    v.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
    v.Set("device_code", device_code)
    v.Set("client_id", clientID)
    tries := 10
    timeout := 2
    for tries > 0 {
        tries--
        resp, err := client.PostForm(op.Token, v)
        if err != nil {
            return nil, err
        } else if 200 <= resp.StatusCode && resp.StatusCode < 300 {
	        responsebody, _ := ioutil.ReadAll(resp.Body)
            res = map[string]any{}
  	        json.Unmarshal(responsebody, &res)
            return res, nil
        } else {
            time.Sleep(time.Duration(timeout) * time.Second)
            continue
        }
    }
    return nil, errors.New("")
}

func post2(token, endpoint string) (res map[string]any, err error) {
	request, _ := http.NewRequest("POST", endpoint, nil)
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Add("Authorization", "Bearer "+token)
  	resp, err := client.Do(request)
  	if err != nil {
  	    return
  	}
	defer resp.Body.Close()
	responsebody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
	    return
	}
    res = map[string]any{}
  	json.Unmarshal(responsebody, &res)
  	PP("post2", responsebody, res)
    return
}

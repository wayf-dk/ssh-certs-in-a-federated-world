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
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

var privateKey = []byte(`-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCaAza9HnNMkWg3a+zYULSZGjTTxfkEJHiDThWJT2k9GwAAAJhom4IiaJuC
IgAAAAtzc2gtZWQyNTUxOQAAACCaAza9HnNMkWg3a+zYULSZGjTTxfkEJHiDThWJT2k9Gw
AAAECXeO3/o6VrHpHiPY95Whg+BjaMgQLQzkbgWr40O7oGXJoDNr0ec0yRaDdr7NhQtJka
NNPF+QQkeINOFYlPaT0bAAAAD3Jvb3RAdGVzdC1hcmtlbgECAwQFBg==
-----END OPENSSH PRIVATE KEY-----
`)

var (
	eppnRegexp = regexp.MustCompile(`[^-a-zA-Z0-9]`)
	tmpl       *template.Template

	//go:embed www
	www embed.FS

	//go:embed assets/ca.template
	caTemplate string
	done       chan bool
)

func main() {
	argv1 := ""
	if len(os.Args) > 1 {
		argv1 = os.Args[1]
	}
	switch argv1 {
	case "AuthorizedKeysCommand":
		authorizedKeysCommand()
	case "CA":
		ca()
	default:
		user, err := user.Current()
		if err != nil {
			log.Fatalf(err.Error())
		}
		switch user.Username {
		case "sshfedlogin":
			sh()
		case "sshgencert":
			generateSSHCertificate()
		case "sshweblogin":
			sshweblogin()
		}
	}
}

func sshweblogin() {
	fn, err := os.CreateTemp("/var/run/sshcerts", "")
	if err != nil {
		log.Fatal(err)
	}

	certTxt, err := os.ReadFile(os.Getenv("SSH_USER_AUTH"))
	if err != nil {
		log.Fatal(err)
	}
	cert, err := unmarshalCert([]byte(certTxt))
	data := cert.Extensions["groups@wayf.dk"]

	if _, err := fn.Write([]byte(data)); err != nil {
		log.Fatal(err)
	}
	if err := fn.Close(); err != nil {
		log.Fatal(err)
	}

	os.Chmod(fn.Name(), 0666)
	_, token := filepath.Split(fn.Name())
	fmt.Print("https://sshsp.lan/sshwebclient.php?token=" + token)
}

func authorizedKeysCommand() {
	if os.Args[2] == "sshgencert" {
		fmt.Println(os.Args[4] + " " + os.Args[3])
	}
}

func ca() {
	tmpl = template.Must(template.New("ca.template").Parse(caTemplate))

	const listenOn = "127.0.0.1:7788"

	fs := http.FileServer(http.FS(www))

	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/www/", fs.ServeHTTP)
	httpMux.Handle("/favicon.ico", http.NotFoundHandler())
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

	fn, err := os.CreateTemp("/var/run/sshca", "")
	if err != nil {
		log.Fatal(err)
	}

	if _, err := fn.Write(data); err != nil {
		log.Fatal(err)
	}
	if err := fn.Close(); err != nil {
		log.Fatal(err)
	}

	os.Chmod(fn.Name(), 0666)
	_, token := filepath.Split(fn.Name())
	principal = eppnRegexp.ReplaceAllString(principal, "_")

	err = tmpl.Execute(w, map[string]any{"token": token, "principal": template.JS(principal)})
	return
}

func generateSSHCertificate() {
	fn := "/var/run/sshca/" + os.Args[2]
	data, err := os.ReadFile(fn)
	if err != nil {
		log.Fatal(err)
	}
	os.Remove(fn)
	attrs := map[string]any{}
	err = json.Unmarshal(data, &attrs)
	if err != nil {
		log.Panic(err)
	}
	principal := eppnRegexp.ReplaceAllString(attrs["eduPersonPrincipalName"].([]interface{})[0].(string), "_")
	bytes, err := os.ReadFile(os.Getenv("SSH_USER_AUTH"))
	if err != nil {
		log.Fatal(err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(bytes)
	if err != nil {
		log.Fatal(err)
	}
	cert := &ssh.Certificate{
		CertType: ssh.UserCert,
		Key:      pub,
		Permissions: ssh.Permissions{
			CriticalOptions: map[string]string{},
			Extensions:      map[string]string{"permit-agent-forwarding": "", "permit-pty": "", "groups@wayf.dk": string(data)},
		},
		KeyId:           principal,
		ValidPrincipals: []string{principal, "sshfedlogin", "sshweblogin"},
		ValidAfter:      uint64(time.Now().Unix() - 60),
		ValidBefore:     uint64(time.Now().Unix() + 24*3600),
	}

	signer, err := ssh.ParsePrivateKey(privateKey)
	if err != nil {
		log.Fatal(err)
	}
	err = cert.SignCert(rand.Reader, signer)
	if err != nil {
		log.Fatal(err)
	}
	certTxt := ssh.MarshalAuthorizedKey(cert)
	fmt.Print(string(certTxt))
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

func sh() {
	certTxt, err := os.ReadFile(os.Getenv("SSH_USER_AUTH"))
	if err != nil {
		log.Fatal(err)
	}
	cert, err := unmarshalCert([]byte(certTxt))
	updateUserAndGroups(cert)
	args := append([]string{"/usr/bin/sudo", "/usr/bin/su", "--login", cert.KeyId}, os.Args[1:]...)
	syscall.Exec("/usr/bin/sudo", args, os.Environ())
}

func updateUserAndGroups(cert *ssh.Certificate) {
	attrs := map[string]any{}
	err := json.Unmarshal([]byte(cert.Extensions["groups@wayf.dk"]), &attrs)
	if err != nil {
		log.Fatalf(err.Error())
	}

	isMemberOf := []string{}
	for _, e := range attrs["isMemberOf"].([]any) {
		g := strings.ToLower(e.(string))
		if len(g) > 32 {
			continue
		}
		isMemberOf = append(isMemberOf, eppnRegexp.ReplaceAllString(g, "_"))
	}
	isMemberOf = append(isMemberOf, cert.KeyId)

	out, err := exec.Command("/usr/bin/sudo", "/usr/sbin/adduser", "--gecos", "", "--disabled-password", cert.KeyId).Output()
	out, err = exec.Command("/usr/bin/sh", "-c", "/usr/bin/getent group | cut -d: -f1").Output()
	existingGroups := strings.Split(string(out), "\n")
	newgroups := difference(isMemberOf, existingGroups)
	for _, grp := range newgroups {
		out, err = exec.Command("/usr/bin/sudo", "/usr/sbin/addgroup", grp).Output()
	}
	usergroups := strings.Join(isMemberOf, ",")
	out, err = exec.Command("/usr/bin/sudo", "/usr/sbin/usermod", "-G", usergroups, cert.KeyId).Output()
}

func unmarshalCert(bytes []byte) (*ssh.Certificate, error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey(bytes)
	if err != nil {
		return nil, err
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("failed to cast to certificate")
	}
	return cert, nil
}

// PP - super simple Pretty Print - using JSON
func PP(i ...interface{}) {
	for _, e := range i {
		s, _ := json.MarshalIndent(e, "", "    ")
		log.Println(string(s))
	}
	return
}

// Set Difference: A - B
func difference(a, b []string) (diff []string) {
	m := make(map[string]bool)

	for _, item := range b {
		m[item] = true
	}

	for _, item := range a {
		if _, ok := m[item]; !ok {
			diff = append(diff, item)
		}
	}
	return
}

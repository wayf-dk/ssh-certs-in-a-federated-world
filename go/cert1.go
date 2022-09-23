package main

import (
	"crypto/rand"
	"embed"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/ssh"
	"html/template"
	"log"
	"net/http"
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

/*
   hengill
   hromundartindur
   blafjoll
   krisuvik
   reykjanes
   svartsengi
   eldey
*/

var (
	demoAttrs = map[string][]string{
		"eduPersonPrincipalName": {"hromundartindur@sshca.lan"},
		"isMemberOf":             {"group-1", "group-2", "group-3", "group-44"},
	}

	eppnRegexp = regexp.MustCompile(`[^-a-z0-9]`)
	tmpl       *template.Template

	//go:embed zzz
	www embed.FS

	//go:embed assets/ca.template
	caTemplate string
)

func main() {
	switch os.Args[1] {
	case  "AuthorizedPrincipalsCommand":
		authorizedPrincipalsCommand()
	case "AuthorizedKeysCommand":
		authorizedKeysCommand()
	case "CA":
		ca()
	case "client":
		client()
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
		}
	}
}

func client() {
	const listenOn = "127.0.0.1:7788"
	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/", clientHandler)

	fmt.Println("Listening on port: " + listenOn)
	err := http.ListenAndServe(listenOn, httpMux)
	fmt.Println("err: ", err)
}

func clientHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	r.ParseForm()
	cmd := r.Form.Get("url")
	fmt.Println(cmd)
	_, err := exec.Command("/bin/sh", "-c", cmd).Output()
	fmt.Println(err)
	cert, err := exec.Command("/bin/sh", "-c", "/usr/local/bin/ssh-keygen -Lf $HOME/.ssh/id_ed25519-cert.pub").Output()
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Write(cert)
}

func ca() {
	tmpl = template.Must(template.New("ca.template").Parse(caTemplate))

	const listenOn = "127.0.0.1:7788"

	fs := http.FileServer(http.FS(www))

	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/zzz/", fs.ServeHTTP)
	httpMux.HandleFunc("/", caHandler)

	fmt.Println("Listening on port: " + listenOn)
	err := http.ListenAndServe(listenOn, httpMux)
	fmt.Println("err: ", err)
}

func caHandler(w http.ResponseWriter, r *http.Request) {
	attrs := demoAttrs
	//attrs = saml2jwt::jwtauth([$scope]);

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
	principal := eppnRegexp.ReplaceAllString(attrs["eduPersonPrincipalName"][0], "_")

	err = tmpl.Execute(w, map[string]string{"token": token, "principal": principal})
	fmt.Println(err)
	return
}

func sh() {
	certTxt, err := os.ReadFile(os.Getenv("SSH_USER_AUTH"))
	if err != nil {
		log.Fatal(err)
	}
	cert, err := unmarshalCert([]byte(certTxt))
	syscall.Exec("/usr/bin/sudo", []string{"/usr/bin/sudo", "/usr/bin/su", "-", cert.KeyId}, os.Environ())
}

func generateSSHCertificate() {
	fn := "/var/run/sshca/" + os.Args[2]
	data, err := os.ReadFile(fn)
	if err != nil {
		log.Fatal(err)
	}
	//os.Remove(fn)
	attrs := map[string][]string{}
	err = json.Unmarshal(data, &attrs)
	if err != nil {
		log.Fatal(err)
	}
	principal := eppnRegexp.ReplaceAllString(attrs["eduPersonPrincipalName"][0], "_")
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
		ValidPrincipals: []string{principal},
		ValidAfter:      uint64(time.Now().Unix() - 60),
		ValidBefore:     uint64(time.Now().Unix() + 1*3600),
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
	fmt.Println(string(certTxt))
}

func authorizedPrincipalsCommand() {
	f, err := os.OpenFile("/var/log/sshca.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()

	log.SetOutput(f)
	cert, _ := unmarshalCert([]byte(os.Args[4] + " " + os.Args[3]))
	updateUserAndGroups(cert)
	fmt.Println(cert.KeyId)
}

func updateUserAndGroups(cert *ssh.Certificate) {
	attrs := map[string][]string{}
	err := json.Unmarshal([]byte(cert.Extensions["groups@wayf.dk"]), &attrs)
	if err != nil {
		log.Fatalf(err.Error())
	}
	attrs["isMemberOf"] = append(attrs["isMemberOf"], cert.KeyId)

	out, err := exec.Command("/usr/sbin/adduser", cert.KeyId).Output()
	out, err = exec.Command("/usr/bin/sh", "-c", "/usr/bin/getent group | cut -d: -f1").Output()
	existingGroups := strings.Split(string(out), "\n")
	newgroups := difference(attrs["isMemberOf"], existingGroups)
	for _, grp := range newgroups {
		out, err = exec.Command("/usr/sbin/addgroup", grp).Output()
	}
	usergroups := strings.Join(attrs["isMemberOf"], ",")
	out, err = exec.Command("/usr/sbin/usermod", "-G", usergroups, cert.KeyId).Output()
}

func authorizedKeysCommand() {
	if os.Args[2] == "sshgencert" {
		fmt.Println(os.Args[4] + " " + os.Args[3])
	}
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

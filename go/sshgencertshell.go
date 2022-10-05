package main

import (
	"crypto/rand"
	_ "embed"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/ssh"
	"log"
	"os"
	"regexp"
	"time"
)

var (
	eppnRegexp = regexp.MustCompile(`[^-a-zA-Z0-9]`)

    //go:embed assets/ca.key
	privateKey []byte
)

func main() {
	generateSSHCertificate()
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

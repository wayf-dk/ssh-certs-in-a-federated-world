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

	ssh2name = map[string]string{
		"ssh-ed25519-cert-v01@openssh.com":                            "ed25519",
		"ecdsa-sha2-nistp256-cert-v01@openssh.com":                    "ecdsa",
		"ecdsa-sha2-nistp384-cert-v01@openssh.com":                    "ecdsa",
		"ecdsa-sha2-nistp521-cert-v01@openssh.com":                    "ecdsa",
		"sk-ssh-ed25519-cert-v01@openssh.com":                         "ed25519_sk",
		"sk-ecdsa-sha2-nistp256-cert-v01@openssh.com":                 "ecdsa_sk",
		"rsa-sha2-512-cert-v01@openssh.com":                           "rsa",
		"rsa-sha2-256-cert-v01@openssh.com":                           "rsa",
		"ssh-ed25519":                                                 "ed25519",
		"ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521": "ecdsa",
		"sk-ecdsa-sha2-nistp256@openssh.com":                          "ecdsa_sk",
		"sk-ssh-ed25519@openssh.com":                                  "ed25519_sk",
		"rsa-sha2-512,rsa-sha2-256":                                   "rsa",
	}
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
	//	os.Remove(fn)
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
	fmt.Printf("%s\n%s", ssh2name[pub.Type()], string(certTxt))
}

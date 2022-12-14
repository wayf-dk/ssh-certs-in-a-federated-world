package main

import (
	"fmt"
	"golang.org/x/crypto/ssh"
	"log"
	"os"
	"path/filepath"
)

func main() {
	sshweblogin()
}

func sshweblogin() {
	certTxt, err := os.ReadFile(os.Getenv("SSH_USER_AUTH"))
	if err != nil {
		log.Fatal(err)
	}

	cert, err := unmarshalCert([]byte(certTxt))
	if err != nil {
		log.Fatal(err)
	}

	data := cert.Extensions["groups@wayf.dk"]

	fn, err := os.CreateTemp("/var/run/sshweblogin", "")
	if err != nil {
		log.Fatal(err)
	}

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

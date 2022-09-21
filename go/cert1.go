package main

import (
  	"encoding/json"
    "fmt"
    "log"
    "os"
    "os/exec"
    "os/user"
    "strings"
    "syscall"
	"golang.org/x/crypto/ssh"
)

func main() {
	user, err := user.Current()
	if err != nil {
		log.Fatalf(err.Error())
	}
	username := user.Username

    switch  {
    case username == "sshfedlogin": sh()
    case os.Args[1] == "AuthorizedPrincipalsCommand": authorizedPrincipalsCommand()
    }
}

func sh() {
    certTxt, err := os.ReadFile(os.Getenv("SSH_USER_AUTH"))
	if err != nil {
		log.Fatal(err)
	}
    cert, err := unmarshalCert([]byte(certTxt))
    syscall.Exec("/usr/bin/sudo", []string{"/usr/bin/sudo", "/usr/bin/su", "-", cert.KeyId}, os.Environ());
}

func authorizedPrincipalsCommand() {
    f, err := os.OpenFile("/var/log/sshca.log", os.O_RDWR | os.O_CREATE | os.O_APPEND, 0666)
    if err != nil {
        log.Fatalf("error opening file: %v", err)
    }
    defer f.Close()

    log.SetOutput(f)
    cert, _ := unmarshalCert([]byte(os.Args[4]+" "+os.Args[3]))
    updateUserAndGroups(cert)
    fmt.Println(cert.KeyId)
}

func updateUserAndGroups(cert *ssh.Certificate) {
    attrs := map[string][]string{}
    err := json.Unmarshal([]byte(cert.Extensions["xgroups@wayf.dk"]), &attrs)
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

func generateCert(pub ssh.PublicKey) *ssh.Certificate {
	permissions := ssh.Permissions{
		CriticalOptions: map[string]string{},
		Extensions: map[string]string{ "permit-agent-forwarding": ""},
	}
	return &ssh.Certificate{
		CertType: ssh.UserCert, Permissions: permissions, Key: pub,
	}
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



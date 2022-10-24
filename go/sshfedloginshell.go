package main

import (
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/ssh"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
)

var (
	eppnRegexp = regexp.MustCompile(`[^-a-zA-Z0-9]`)
)

func main() {
	sshfedloginshell()
}

func sshfedloginshell() {
	certTxt, err := os.ReadFile(os.Getenv("SSH_USER_AUTH"))
	if err != nil {
		log.Fatal(err)
	}
	cert, err := unmarshalCert([]byte(certTxt))
	updateUserAndGroups(cert)
	args := append([]string{"sudo", "/bin/su", "--login", cert.KeyId}, os.Args[1:]...)
	fmt.Println(os.Args, args)
	syscall.Exec("/usr/bin/sudo", args, os.Environ())
}

func updateUserAndGroups(cert *ssh.Certificate) {
	out, err := exec.Command("/usr/bin/sudo", "/usr/sbin/adduser", "--gecos", "", "--disabled-password", cert.KeyId).Output()
	attrs := map[string]any{}
	err = json.Unmarshal([]byte(cert.Extensions["groups@wayf.dk"]), &attrs)
	if err != nil {
		return // log.Fatalf(err.Error())
	}

	if attrs["isMemberOf"] != nil {
		isMemberOf := []string{}
		for _, e := range attrs["isMemberOf"].([]any) {
			g := strings.ToLower(e.(string))
			if len(g) > 32 {
				continue
			}
			isMemberOf = append(isMemberOf, eppnRegexp.ReplaceAllString(g, "_"))
		}
		isMemberOf = append(isMemberOf, cert.KeyId)

		out, err = exec.Command("/usr/bin/sh", "-c", "/usr/bin/getent group | cut -d: -f1").Output()
		existingGroups := strings.Split(string(out), "\n")
		newgroups := difference(isMemberOf, existingGroups)
		for _, grp := range newgroups {
			out, err = exec.Command("/usr/bin/sudo", "/usr/sbin/addgroup", grp).Output()
		}
		usergroups := strings.Join(isMemberOf, ",")
		out, err = exec.Command("/usr/bin/sudo", "/usr/sbin/usermod", "-G", usergroups, cert.KeyId).Output()
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

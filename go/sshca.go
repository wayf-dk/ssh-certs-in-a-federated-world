package main

import (
	"crypto"
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
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

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
	ca()
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

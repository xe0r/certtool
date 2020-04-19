// +build js,wasm
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"syscall/js"
	"time"
)

func processPEM(this js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return nil
	}

	content := []byte(args[0].String())
	var blk *pem.Block
	blk, content = pem.Decode(content)

	if blk == nil {
		fmt.Println("No pem found")
		return nil
	}
	fmt.Println("processPEM", blk.Type)

	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		fmt.Println("Unable to parse")
		return nil
	}
	res := make([]interface{}, 0)
	res = append(res, []interface{}{"Version", fmt.Sprint(cert.Version)})

	res = append(res, []interface{}{"Subject", cert.Subject.ToRDNSequence().String()})
	res = append(res, []interface{}{"Issuer", cert.Issuer.ToRDNSequence().String()})

	for _, name := range cert.DNSNames {
		res = append(res, []interface{}{"DNS name", name})
	}

	res = append(res, []interface{}{"Not before", cert.NotBefore.Format(time.UnixDate)})
	res = append(res, []interface{}{"Not after", cert.NotAfter.Format(time.UnixDate)})

	res = append(res, []interface{}{"Signature algorithm", cert.SignatureAlgorithm.String()})
	res = append(res, []interface{}{"Public key algorithm", cert.PublicKeyAlgorithm.String()})

	res = append(res, []interface{}{"Serial", hex.EncodeToString(cert.SerialNumber.Bytes())})

	for _, name := range cert.CRLDistributionPoints {
		res = append(res, []interface{}{"CRL distribution point", name})
	}

	return res
}

func generateCert(this js.Value, args []js.Value) interface{} {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		fmt.Println("Can't generate")
		return nil
	}
	data := x509.MarshalPKCS1PrivateKey(key)
	keyblk := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: data,
	}

	hostname := "localhost"
	name := pkix.Name{
		CommonName: hostname,
	}
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),

		Subject: name,
		Issuer:  name,

		NotBefore: time.Now().AddDate(0, 0, -1),
		NotAfter:  time.Now().AddDate(0, 3, 0),

		SignatureAlgorithm: x509.SHA256WithRSA,

		DNSNames: []string{hostname},

		KeyUsage:    x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certdata, err := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
	if err != nil {
		fmt.Println("Can't create cert")
		return nil
	}

	certblk := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certdata,
	}

	return string(pem.EncodeToMemory(keyblk)) + string(pem.EncodeToMemory(certblk))
}

func registerCallbacks() {
	js.Global().Set("processPEM", js.FuncOf(processPEM))
	js.Global().Set("generateCert", js.FuncOf(generateCert))
}

func main() {
	c := make(chan struct{}, 0)

	fmt.Println("Golang loaded")

	registerCallbacks()

	<-c
}

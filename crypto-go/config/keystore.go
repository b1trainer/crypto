package config

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"os"

	"software.sslmate.com/src/go-pkcs12"
)

type Certs struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	X509       *x509.Certificate
}

func LoadKeystore(ksPath string, ksPass string) (*Certs, error) {
	data, err := os.ReadFile(ksPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read keystore: %w", err)
	}

	pKInterface, cert, err := pkcs12.Decode(data, ksPass)
	if err != nil {
		return nil, fmt.Errorf("cannot decode PKCS12: %w", err)
	}

	if cert == nil {
		return nil, fmt.Errorf("no certificate found in keystore")
	}

	rsaPrivate, ok := pKInterface.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not RSA (type: %T)", pKInterface)
	}

	rsaPub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not RSA (type: %T)", cert.PublicKey)
	}

	return &Certs{
		PrivateKey: rsaPrivate,
		PublicKey:  rsaPub,
		X509:       cert,
	}, nil
}

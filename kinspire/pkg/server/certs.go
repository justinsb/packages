package server

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"time"

	"github.com/justinsb/packages/kinspire/pkg/certs"
)

type ServerCertificates struct {
	caCertificates []*x509.Certificate

	serverCert *x509.Certificate
	serverKey  crypto.PrivateKey

	TLSCertificate tls.Certificate
}

func CreateServerCertificates(ctx context.Context, signer *LocalSigner) (*ServerCertificates, error) {
	serverTemplate := x509.Certificate{
		Subject: pkix.Name{
			CommonName: "kinspire-server.auth-system",
		},
		DNSNames:  []string{"kinspire-server.auth-system"},
		NotBefore: time.Now().Add(-10 * time.Minute),
		NotAfter:  time.Now().AddDate(10, 0, 0),

		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  false,
		BasicConstraintsValid: true,
	}

	caCertificates, err := signer.GetCACertificates(ctx)
	if err != nil {
		return nil, err
	}

	serverCert, serverKey, err := signer.CreateCertificate(ctx, serverTemplate)
	if err != nil {
		return nil, err
	}

	// There might be a better way to do this, but this is pretty robust
	serverCertBytes, err := certs.EncodeCertificate(serverCert)
	if err != nil {
		return nil, err
	}
	serverKeyBytes, err := certs.EncodePrivateKey(serverKey)
	if err != nil {
		return nil, err
	}
	tlsCertificate, err := tls.X509KeyPair(serverCertBytes, serverKeyBytes)
	if err != nil {
		return nil, err
	}

	return &ServerCertificates{
		caCertificates: caCertificates,
		serverCert:     serverCert,
		serverKey:      serverKey,
		TLSCertificate: tlsCertificate,
	}, nil
}

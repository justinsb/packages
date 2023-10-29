package server

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"

	"github.com/justinsb/packages/kinspire/pkg/certs"
)

type LocalSigner struct {
	caCerts []*x509.Certificate

	signerCert *x509.Certificate
	signerKey  crypto.PrivateKey
}

func NewLocalSigner() (*LocalSigner, error) {
	caDir := "/secrets/ca"

	var caCertificates []*x509.Certificate
	{
		p := filepath.Join(caDir, "ca.crt")
		caBytes, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("reading file %q: %w", p, err)
		}
		caCertificates, err = certs.DecodeCertificates(caBytes)
		if err != nil {
			return nil, fmt.Errorf("error adding certificates from %q", p)
		}
	}

	signerCert, err := certs.LoadCertificate(filepath.Join(caDir, "signing.crt"))
	if err != nil {
		return nil, err
	}
	signerKey, err := certs.LoadPrivateKey(filepath.Join(caDir, "signing.key"))
	if err != nil {
		return nil, err
	}

	return &LocalSigner{
		caCerts:    caCertificates,
		signerKey:  signerKey,
		signerCert: signerCert,
	}, nil
}

func (s *LocalSigner) GetCACertificates(ctx context.Context) ([]*x509.Certificate, error) {
	return s.caCerts, nil
}

func (s *LocalSigner) CreateCertificate(ctx context.Context, template x509.Certificate) (*x509.Certificate, crypto.PrivateKey, error) {
	return certs.CreateCertificate(template, s.signerCert, s.signerKey)
}

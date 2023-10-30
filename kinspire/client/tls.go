package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
)

func getKinspireServerTLSConfig(ctx context.Context, spireConfig *spireConfigMap) (*tls.Config, error) {
	caCrt := spireConfig.config.Data["ca.crt"]
	if len(caCrt) == 0 {
		return nil, fmt.Errorf("ca.crt not found in spire config")
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM([]byte(caCrt)) {
		return nil, fmt.Errorf("failed to add spire server CA certificate")
	}

	// Create the credentials and return it
	tlsConfig := &tls.Config{
		RootCAs: certPool,
	}
	return tlsConfig, nil
}

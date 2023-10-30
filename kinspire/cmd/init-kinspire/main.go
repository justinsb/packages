package main

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"

	"github.com/justinsb/packages/kinspire/pkg/certs"
)

func main() {
	err := run(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	trustDomain := "spiffe://k8s.local" // TODO: Get from kube cluster?  Or from the root ca?
	flag.Parse()

	trustDomainURL, err := url.Parse(trustDomain)
	if err != nil {
		return fmt.Errorf("parsing trust domain %q: %w", trustDomain, err)
	}

	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		if home := homedir.HomeDir(); home != "" {
			kubeconfig = filepath.Join(home, ".kube", "config")
		}
	}
	flag.StringVar(&kubeconfig, "kubeconfig", kubeconfig, "absolute path to the kubeconfig file")
	flag.Parse()

	// use the current context in kubeconfig
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return fmt.Errorf("building config: %w", err)
	}

	// create the clientset
	kube, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("building client: %w", err)
	}

	caTemplate := x509.Certificate{
		Subject: pkix.Name{
			CommonName: trustDomainURL.String(),
		},
		URIs:      []*url.URL{trustDomainURL},
		NotBefore: time.Now().Add(-10 * time.Minute),
		NotAfter:  time.Now().AddDate(10, 0, 0),

		// KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		// ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth | x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	caCert, caKey, err := certs.CreateCertificate(caTemplate, nil, nil)
	if err != nil {
		return err
	}

	caCertBytes, err := certs.PEMEncodeCertificate(caCert)
	if err != nil {
		return err
	}

	caKeyBytes, err := certs.EncodePrivateKey(caKey)
	if err != nil {
		return err
	}

	secret := &corev1.Secret{}
	secret.Name = "kinspire-ca"
	secret.Data = make(map[string][]byte)
	secret.Data["ca.crt"] = caCertBytes
	secret.Data["signing.crt"] = caCertBytes
	secret.Data["signing.key"] = caKeyBytes

	if _, err := kube.CoreV1().Secrets("auth-system").Create(ctx, secret, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("creating secret: %w", err)
	}

	cm := &corev1.ConfigMap{}
	cm.Name = "kinspire"
	cm.Data = make(map[string]string)
	cm.Data["ca.crt"] = string(caCertBytes)

	if _, err := kube.CoreV1().ConfigMaps("auth-system").Create(ctx, cm, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("creating configmap: %w", err)
	}

	return nil
}

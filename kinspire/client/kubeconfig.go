package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
)

type spireConfigMap struct {
	k8s       *simpleKubeClient
	namespace string
	name      string

	config *configMap
}

func (c *spireConfigMap) ServerAddr() (string, error) {
	return "tcp://kinspire-server.auth-system:443", nil

	// Workaround for "workload endpoint tcp socket URI host component must be an IP:port"
	// ips, err := net.LookupIP("kinspire-server.auth-system")
	// if err != nil {
	// 	return "", fmt.Errorf("looking up address for auth-system/kinspire-server service: %w", err)
	// }
	// if len(ips) != 1 {
	// 	return "", fmt.Errorf("expected exactly one address for service auth-system/kinspire-server, got %v", ips)
	// }

	// ip := ips[0]
	// return fmt.Sprintf("tcp://%v:443", ip), nil
}

func newSpireConfig(ctx context.Context) (*spireConfigMap, error) {
	k8s, err := newInClusterClient(ctx)
	if err != nil {
		return nil, err
	}

	namespace := "auth-system"
	name := "kinspire"

	cm, err := k8s.loadConfigMap(ctx, namespace, name)
	if err != nil {
		return nil, err
	}

	return &spireConfigMap{
		k8s:       k8s,
		namespace: namespace,
		name:      name,
		config:    cm,
	}, nil
}

type simpleKubeClient struct {
	endpoint   string
	httpClient *http.Client
}

type configMap struct {
	Data map[string]string `json:"data,omitempty"`
}

func newInClusterClient(ctx context.Context) (*simpleKubeClient, error) {
	endpoint := os.Getenv("KUBERNETES_SERVICE_HOST")
	if endpoint == "" {
		endpoint = "kubernetes.default"
	}

	if ip := net.ParseIP(endpoint); ip != nil {
		if ip.To4() == nil {
			endpoint = "[" + endpoint + "]"
		}
	}
	endpoint = "https://" + endpoint + "/"

	p := "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("reading file %q: %w", p, err)
	}

	rootCAs := x509.NewCertPool()
	if !rootCAs.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("adding trusted CAs: %w", err)
	}

	tlsClientConfig := &tls.Config{
		RootCAs: rootCAs,
	}

	c := &simpleKubeClient{}
	c.endpoint = endpoint
	c.httpClient = &http.Client{}
	c.httpClient.Transport = &http.Transport{
		TLSClientConfig: tlsClientConfig,
	}

	return c, nil
}

func (p *simpleKubeClient) loadConfigMap(ctx context.Context, namespace string, name string) (*configMap, error) {
	u := p.endpoint + "api/v1/namespaces/" + namespace + "/configmaps/" + name
	b, err := p.getURL(ctx, u)
	if err != nil {
		return nil, fmt.Errorf("reading configmap %s/%s: %w", namespace, name, err)
	}
	obj := &configMap{}
	if err := json.Unmarshal(b, obj); err != nil {
		return nil, fmt.Errorf("parsing configmap %s/%s: %w", namespace, name, err)
	}
	return obj, nil
}

func (c *simpleKubeClient) loadAuthorization() (string, error) {
	p := "/var/run/secrets/kubernetes.io/serviceaccount/token"
	b, err := os.ReadFile(p)
	if err != nil {
		return "", fmt.Errorf("reading file %q: %w", p, err)
	}
	return "Bearer " + string(b), nil
}

func (c *simpleKubeClient) getURL(ctx context.Context, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}

	authorization, err := c.loadAuthorization()
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", authorization)

	response, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("doing http request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("unexpected http response status %q", response.Status)
	}

	b, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("reading http response body: %w", err)
	}

	return b, nil
}

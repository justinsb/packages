package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"k8s.io/klog/v2"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"

	"github.com/justinsb/packages/kinspire/client"

	"github.com/justinsb/packages/alpha/gitea/pkg/ini"
)

func main() {
	if err := run(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	// klog.InitFlags(nil)
	// flag.Parse()

	if err := client.SPIFFE.Init(ctx); err != nil {
		return err
	}

	gitea := &Gitea{
		ConfigDir:  "/config",
		SocketsDir: "/sockets",
	}

	if err := gitea.mkdirs(ctx); err != nil {
		return err
	}
	if err := gitea.writeGiteaConfig(ctx); err != nil {
		return err
	}

	proxy := &GiteaProxy{}
	go func() {
		if err := proxy.Run(ctx); err != nil {
			klog.Fatalf("error running http proxy: %v", err)
		}
	}()
	go func() {
		if err := gitea.runPostgresProxy(ctx); err != nil {
			klog.Fatalf("error running postgres proxy: %v", err)
		}
	}()

	configPath := filepath.Join(gitea.ConfigDir, "gitea.ini")
	args := []string{"--config", configPath}

	cmd := exec.CommandContext(ctx, "/app/gitea/gitea", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	klog.Infof("starting gitea: %v", strings.Join(cmd.Args, " "))
	if err := cmd.Run(); err != nil {
		return err
	}

	return nil
}

func mkdirAll(dir string, fileMode os.FileMode) error {
	klog.Infof("setting dir %q to mode %v", dir, fileMode)
	if err := os.MkdirAll(dir, fileMode); err != nil {
		return fmt.Errorf("error doing MkdirAll(%q, %d): %w", dir, fileMode, err)
	}
	if err := os.Chmod(dir, fileMode); err != nil {
		return fmt.Errorf("error doing Chmod(%q, %d): %w", dir, fileMode, err)
	}
	return nil
}

type Gitea struct {
	ConfigDir  string
	SocketsDir string
}

func (c *Gitea) mkdirs(ctx context.Context) error {
	if err := mkdirAll(c.ConfigDir, 0750); err != nil {
		return err
	}
	// if err := os.Chown(pgdata, pgUID, pgGID); err != nil {
	// 	return fmt.Errorf("error doing Chown(%q, %d, %d): %w", pgdata, pgUID, pgGID, err)
	// }
	if err := mkdirAll(c.SocketsDir, 0750); err != nil {
		return err
	}
	if err := mkdirAll(filepath.Join(c.SocketsDir, "postgres"), 0750); err != nil {
		return err
	}
	// if err := os.Chown(pgdata, pgUID, pgGID); err != nil {
	// 	return fmt.Errorf("error doing Chown(%q, %d, %d): %w", pgdata, pgUID, pgGID, err)
	// }
	return nil
}

func (c *Gitea) runPostgresProxy(ctx context.Context) error {
	proxy := &PostgresProxy{
		Listen:      filepath.Join(c.SocketsDir, "postgres", ".s.PGSQL.5432"),
		Destination: "postgres:5432",
	}
	return proxy.Run(ctx)
}

func (c *Gitea) writeGiteaConfig(ctx context.Context) error {
	config := ini.New()

	db := config.Section("database")
	db.Set("DB_TYPE", "postgres")
	db.Set("HOST", "/sockets/postgres")
	db.Set("NAME", "gitea")
	db.Set("USER", "gitea")
	db.Set("SSL_MODE", "none")
	db.Set("LOG_SQL", "true") // Really only for debugging

	server := config.Section("server")
	server.Set("APP_DATA_PATH", "/volumes/data")
	// TODO: Where should we store the SSH secrets?  (And are these really the secrets?)
	server.Set("SSH_ROOT_PATH", "/volumes/data/ssh")

	lfs := config.Section("lfs")
	lfs.Set("PATH", "/volumes/data/lfs")

	log := config.Section("log")
	log.Set("ROOT_PATH", "/volumes/data/log")

	// TODO: maybe we don't need the proxy?
	//     ; CERT_FILE = https/cert.pem
	// ; KEY_FILE = https/key.pem

	var bb bytes.Buffer
	if err := config.WriteTo(&bb); err != nil {
		return fmt.Errorf("writing config: %w", err)
	}

	p := filepath.Join(c.ConfigDir, "gitea.ini")
	klog.Infof("config is:\n%v", bb.String())
	if err := os.WriteFile(p, bb.Bytes(), 0644); err != nil {
		return fmt.Errorf("error writing file %q: %w", p, err)
	}
	return nil
}

type GiteaProxy struct {
}

func (p *GiteaProxy) Run(ctx context.Context) error {
	klog.Infof("building proxy")
	proxy, err := p.buildProxy()
	if err != nil {
		return err
	}

	// Allowed SPIFFE ID
	clientID := spiffeid.RequireFromString("spiffe://k8s.local/ns/default/sa/gateway-instance")

	source := client.SPIFFE.Source()

	klog.Infof("creating httpserver")
	// Create a `tls.Config` to allow mTLS connections, and verify that presented certificate has SPIFFE ID `spiffe://example.org/client`
	tlsConfig := tlsconfig.MTLSServerConfig(source, source, tlsconfig.AuthorizeID(clientID))
	server := &http.Server{
		Addr:              ":8443",
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: time.Second * 10,
		Handler:           proxy,
	}

	klog.Infof("listening on %s", server.Addr)
	if err := server.ListenAndServeTLS("", ""); err != nil {
		return fmt.Errorf("failed to serve: %w", err)
	}

	return nil
}

func (p *GiteaProxy) buildProxy() (http.Handler, error) {
	target := "http://127.0.0.1:3000"
	targetURL, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("parsing url %q: %w", targetURL, err)
	}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			// klog.Infof("request is in=%+v, out=%+v", r.In, r.Out)
			// klog.Infof("r.in.tls = %+v", r.In.TLS)
			// klog.Infof("r.in.tls.peerCertificates = %+v", r.In.TLS.PeerCertificates)
			r.SetURL(targetURL)
			// r.Out.Host = r.In.Host // if desired
		},
	}
	return proxy, nil
}

type PostgresProxy struct {
	Listen      string
	Destination string
}

func (p *PostgresProxy) Run(ctx context.Context) error {
	klog.Infof("building proxy")

	// Allowed SPIFFE ID
	targetID := spiffeid.RequireFromString("spiffe://k8s.local/ns/gitea/sa/postgres")

	source := client.SPIFFE.Source()

	klog.Infof("creating httpserver")
	// Create a `tls.Config` to allow mTLS connections, and verify that presented certificate has SPIFFE ID `spiffe://example.org/client`
	tlsConfig := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeID(targetID))

	listener, err := net.ListenUnix("unix", &net.UnixAddr{Net: "unix", Name: p.Listen})
	if err != nil {
		return fmt.Errorf("listening on unix://%s: %w", p.Listen, err)
	}

	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			return fmt.Errorf("failed to accept connection: %w", err)
		}

		c := &postgresProxyConnection{
			incoming:             conn,
			destination:          p.Destination,
			destinationTLSConfig: tlsConfig,
		}
		go func() {
			if err := c.run(ctx); err != nil {
				klog.Warningf("error forwarding postgres connection: %v", err)
			}
		}()
	}
}

type postgresProxyConnection struct {
	incoming             net.Conn
	destination          string
	destinationTLSConfig *tls.Config
}

func (p *postgresProxyConnection) run(ctx context.Context) error {
	defer func() {
		if err := p.incoming.Close(); err != nil {
			klog.Warningf("error closing incoming connection: %v", err)
		}
	}()

	remote, err := net.Dial("tcp", p.destination)
	if err != nil {
		return fmt.Errorf("dialing tcp://%s: %w", p.destination, err)
	}

	if p.destinationTLSConfig != nil {
		// postgres doesn't speak "plain" TLS, there's a SSLRequest packet that has to happen first
		// https://www.postgresql.org/docs/current/protocol-message-formats.html
		req := []byte{
			// Int32(8): Length of message contents in bytes, including self.
			0x00, 0x00, 0x00, 0x08,
			// Int32(80877103): The SSL request code. The value is chosen to contain 1234 in the most significant 16 bits, and 5679 in the least significant 16 bits. (To avoid confusion, this code must not be the same as any protocol version number.)
			0x04, 0xd2, 0x16, 0x2f,
		}

		if _, err := remote.Write(req); err != nil {
			return fmt.Errorf("writing SSLRequest packet: %w", err)
		}
		response := make([]byte, 1)
		if _, err := remote.Read(response); err != nil {
			return fmt.Errorf("reading SSLRequest response: %w", err)
		}

		// The server then responds with a single byte containing S or N, indicating that it is willing or unwilling to perform SSL, respectively. The frontend might close the connection at this point if it is dissatisfied with the response.
		switch response[0] {
		case 'N':
			return fmt.Errorf("postgres server rejected SSL request")

		case 'S':
			// Can now start SSL handshake
		default:
			return fmt.Errorf("postgres server gave unknown response %x to SSL request", response[0])
		}

		tlsConfig := p.destinationTLSConfig.Clone() // TODO: Do we need to clone?
		tlsConnection := tls.Client(remote, tlsConfig)
		if err := tlsConnection.HandshakeContext(ctx); err != nil {
			// TODO: defer?
			remote.Close()

			return fmt.Errorf("failed to perform tls handshake: %w", err)
		}

		remote = tlsConnection
	}

	errors := make(chan error, 2)
	go func() {
		if err := p.pipe(p.incoming, remote); err != nil {
			errors <- err
		}
	}()
	go func() {
		if err := p.pipe(remote, p.incoming); err != nil {
			errors <- err
		}
	}()

	firstError := <-errors
	return firstError
}

func (p *postgresProxyConnection) pipe(src, dst io.ReadWriter) error {
	buffer := make([]byte, 0xffff)
	for {
		n, err := src.Read(buffer)
		if err != nil {
			return fmt.Errorf("reading: %w", err)
		}
		data := buffer[:n]

		// klog.Infof("forwarding %d bytes", n)

		if _, err := dst.Write(data); err != nil {
			return fmt.Errorf("writing: %w", err)
		}
	}
}

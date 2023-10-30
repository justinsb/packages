package client

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"google.golang.org/grpc"
	"k8s.io/klog/v2"
)

type SPIFFESource struct {
	// ctx    context.Context
	cancel func()

	spiffeClient workload.SpiffeWorkloadAPIClient

	mutex sync.Mutex
	last  *workload.X509SVIDResponse
}

func newSPIFFESource(grpcConn *grpc.ClientConn) (*SPIFFESource, error) {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	s := &SPIFFESource{
		cancel: cancel,
	}
	s.spiffeClient = workload.NewSpiffeWorkloadAPIClient(grpcConn)

	go s.watchUntilContextClosed(ctx)

	return s, nil
}

func (s *SPIFFESource) waitForFirstUpdate(ctx context.Context) error {
	for {
		if s.last != nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		time.Sleep(1 * time.Second)
	}
}

func (s *SPIFFESource) watchUntilContextClosed(ctx context.Context) error {
	for {
		if err := s.watchOnce(ctx); err != nil {
			klog.Infof("error from spiffe watch: %v", err)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		time.Sleep(1 * time.Second)
	}
}

func (s *SPIFFESource) watchOnce(ctx context.Context) error {
	stream, err := s.spiffeClient.FetchX509SVID(ctx, &workload.X509SVIDRequest{})
	if err != nil {
		return fmt.Errorf("fetching x509 svid: %w", err)
	}
	defer stream.CloseSend()

	for {
		msg, err := stream.Recv()
		if err != nil {
			return fmt.Errorf("reading from x509 svid stream: %w", err)
		}
		s.mutex.Lock()
		s.last = msg
		s.mutex.Unlock()
		klog.Infof("got %T message from x509 svid stream", msg)
	}
}

func (s *SPIFFESource) Close() error {
	s.cancel()
	return nil
}

var _ x509svid.Source = &SPIFFESource{}
var _ x509bundle.Source = &SPIFFESource{}

// GetX509SVID returns an X509-SVID from the source.
func (s *SPIFFESource) GetX509SVID() (*x509svid.SVID, error) {
	s.mutex.Lock()
	last := s.last
	s.mutex.Unlock()

	if last == nil {
		return nil, fmt.Errorf("svid not yet received")
	}
	if len(last.Svids) == 0 {
		return nil, fmt.Errorf("svid was not included in update")
	}
	if len(last.Svids) > 1 {
		return nil, fmt.Errorf("multiple svids found in update")
	}
	certBytes := last.Svids[0].X509Svid
	keyBytes := last.Svids[0].X509SvidKey

	svid, err := x509svid.ParseRaw(certBytes, keyBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing svid data: %w", err)
	}
	return svid, nil
}

// GetX509BundleForTrustDomain returns the X.509 bundle for the given trust
// domain.
func (s *SPIFFESource) GetX509BundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	s.mutex.Lock()
	last := s.last
	s.mutex.Unlock()

	if last == nil {
		return nil, fmt.Errorf("svid not yet received")
	}
	if len(last.Svids) == 0 {
		return nil, fmt.Errorf("svid was not included in update")
	}
	if len(last.Svids) > 1 {
		return nil, fmt.Errorf("multiple svids found in update")
	}

	trustDomain, err := spiffeid.TrustDomainFromString(last.Svids[0].SpiffeId)
	if err != nil {
		return nil, fmt.Errorf("parsing svid domain %q: %w", last.Svids[0].SpiffeId, err)
	}
	bundle, err := x509bundle.ParseRaw(trustDomain, last.Svids[0].Bundle)
	if err != nil {
		return nil, fmt.Errorf("parsing bundle data: %w", err)
	}
	return bundle, nil
}

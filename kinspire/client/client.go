package client

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"k8s.io/klog/v2"
)

type spiffe struct {
	source *SPIFFESource

	configClient *spireConfigMap
}

var SPIFFE spiffe

// func init() {
// 	ctx := context.Background()
// 	// TODO: Hook up to sockets?  Call init from main?
// 	if err := SPIFFE.Init(ctx); err != nil {
// 		klog.Fatalf("failed to init spiffe: %v", err)
// 	}
// }

func (s *spiffe) Source() *SPIFFESource {
	return s.source
}

func (s *spiffe) Init(ctx context.Context) error {
	spireConfig, err := newSpireConfig(ctx)
	if err != nil {
		return err
	}

	addr, err := spireConfig.ServerAddr()
	if err != nil {
		return err
	}

	tlsConfig, err := getKinspireServerTLSConfig(ctx, spireConfig)
	if err != nil {
		return err
	}
	// tlsConfig.InsecureSkipVerify = true

	tlsCredentials := credentials.NewTLS(tlsConfig)

	var grpcOptions []grpc.DialOption

	grpcOptions = append(grpcOptions, grpc.WithTransportCredentials(tlsCredentials))
	grpcOptions = append(grpcOptions, grpc.WithUnaryInterceptor(s.unaryInterceptor))
	grpcOptions = append(grpcOptions, grpc.WithStreamInterceptor(s.streamInterceptor))
	grpcConn, err := grpc.DialContext(ctx, strings.TrimPrefix(addr, "tcp://"), grpcOptions...)
	if err != nil {
		return fmt.Errorf("dialing grpc: %w", err)
	}
	source, err := newSPIFFESource(grpcConn)
	if err != nil {
		return err
	}
	s.source = source

	// client, err := workloadapi.New(ctx, workloadapi.WithAddr(addr), workloadapi.WithDialOptions(grpcOptions...), workloadapi.WithLogger(logger.Std))
	// if err != nil {
	// 	return fmt.Errorf("creating spire client for %q: %w", addr, err)
	// }

	// klog.Infof("creating x509 source with %q", addr)
	// // Create a `workloadapi.X509Source`, it will connect to Workload API using provided socket.
	// // If socket path is not defined using `workloadapi.SourceOption`, value from environment variable `SPIFFE_ENDPOINT_SOCKET` is used.
	// source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClient(client))
	// if err != nil {
	// 	return fmt.Errorf("unable to create X509Source: %w", err)
	// }

	if err := source.waitForFirstUpdate(ctx); err != nil {
		return err
	}

	svid, err := source.GetX509SVID()
	if err != nil {
		return err
	}
	klog.Infof("svid is %v", svid.ID)

	return nil
}

func (s *spiffe) Close() error {
	var errs []error
	if s.source != nil {
		if err := s.source.Close(); err != nil {
			errs = append(errs, err)
		} else {
			s.source = nil
		}
	}
	return errors.Join(errs...)
}

func (s *spiffe) unaryInterceptor(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	p := "/var/run/secrets/kubernetes.io/serviceaccount/token"
	b, err := os.ReadFile(p)
	if err != nil {
		return fmt.Errorf("reading file %q: %w", p, err)
	}
	accessToken := string(b)
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", accessToken)
	return invoker(ctx, method, req, reply, cc, opts...)
}

func (s *spiffe) streamInterceptor(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	p := "/var/run/secrets/kubernetes.io/serviceaccount/token"
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("reading file %q: %w", p, err)
	}
	accessToken := string(b)
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", accessToken)
	return streamer(ctx, desc, cc, method, opts...)
}

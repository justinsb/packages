package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"

	api "github.com/justinsb/packages/kinspire/api"
	"github.com/justinsb/packages/kinspire/pkg/server"
)

func main() {
	if err := run(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	listen := ":8443"
	trustDomain := "spiffe://k8s.local" // TODO: Get from kube cluster?
	flag.Parse()

	trustDomainURL, err := url.Parse(trustDomain)
	if err != nil {
		return fmt.Errorf("parsing trust domain %q: %w", trustDomain, err)
	}

	restConfig, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("getting kube config: %w", err)
	}
	scheme := runtime.NewScheme()
	if err := api.AllKinds.AddToScheme(scheme); err != nil {
		return fmt.Errorf("building kube scheme: %w", err)
	}
	// TODO: Caching?
	kubeClient, err := client.New(restConfig, client.Options{
		Scheme: scheme,
	})
	if err != nil {
		return fmt.Errorf("building kube client: %w", err)
	}
	typedKubeClient, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("building typed kube client: %w", err)
	}

	signer, err := server.NewLocalSigner()
	if err != nil {
		return err
	}

	servingCert, err := server.CreateServerCertificates(ctx, signer)
	if err != nil {
		return err
	}

	var opts []grpc.ServerOption
	creds := credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{servingCert.TLSCertificate}})
	opts = []grpc.ServerOption{grpc.Creds(creds)}

	grpcServer := grpc.NewServer(opts...)
	s, err := server.NewSPIREServer(kubeClient, typedKubeClient, signer, trustDomainURL)
	if err != nil {
		return err
	}

	s.RegisterGRPC(grpcServer)

	klog.Infof("listening on %v", listen)
	lis, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("listening on %q: %w", listen, err)
	}
	if err := grpcServer.Serve(lis); err != nil {
		return fmt.Errorf("serving GRPC: %w", err)
	}
	return nil
}

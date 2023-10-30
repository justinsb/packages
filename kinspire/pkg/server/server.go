package server

import (
	"bytes"
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/prototext"
	authenticationv1 "k8s.io/client-go/kubernetes/typed/authentication/v1"
	"k8s.io/klog/v2"
)

type SPIREServer struct {
	authenticationClient authenticationv1.AuthenticationV1Interface
	signer               *LocalSigner
	trustDomain          *url.URL
	workload.UnimplementedSpiffeWorkloadAPIServer
}

func NewSPIREServer(authenticationClient authenticationv1.AuthenticationV1Interface, signer *LocalSigner, trustDomain *url.URL) (*SPIREServer, error) {
	return &SPIREServer{
		authenticationClient: authenticationClient,
		signer:               signer,
		trustDomain:          trustDomain,
	}, nil
}

func (s *SPIREServer) RegisterGRPC(grpcServer *grpc.Server) {
	workload.RegisterSpiffeWorkloadAPIServer(grpcServer, s)
}

func (s *SPIREServer) FetchX509SVID(req *workload.X509SVIDRequest, stream workload.SpiffeWorkloadAPI_FetchX509SVIDServer) error {
	ctx := stream.Context()

	var authorization []string
	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		authorization = md.Get("authorization")
	}

	if len(authorization) > 1 {
		return status.Errorf(codes.InvalidArgument, "multiple authorization headers found")
	}

	if len(authorization) == 0 {
		return status.Errorf(codes.Unauthenticated, "authorization not found")
	}

	auth, err := s.verifyKubernetesServiceAccountToken(ctx, authorization[0])
	if err != nil {
		klog.Warningf("error verifying token: %v", err)
		return status.Errorf(codes.Internal, "error verifying token")
	}
	if auth == nil {
		return status.Errorf(codes.Unauthenticated, "authentication failed")
	}

	klog.Infof("req %v", prototext.Format(req))
	klog.Infof("auth %v", auth)

	expectedAudience := "kubernetes.svc.default"
	hasAudience := false
	for _, aud := range auth.Audiences {
		if aud == expectedAudience {
			hasAudience = true
		}
	}

	if !hasAudience {
		klog.Warningf("user did not have expected audience %q: %+v", expectedAudience, auth)
		return status.Errorf(codes.PermissionDenied, "permission denied")
	}

	var spiffeID *url.URL
	userTokens := strings.Split(auth.UserName, ":")
	if len(userTokens) == 4 && userTokens[0] == "system" && userTokens[1] == "serviceaccount" {
		ns := userTokens[2]
		name := userTokens[3]

		spiffeID = s.trustDomain.JoinPath("ns", ns, "sa", name)
	}

	if spiffeID == nil {
		klog.Warningf("cannot map user %+v to spiffe", auth)
		return status.Errorf(codes.PermissionDenied, "permission denied")
	}

	klog.Infof("mapped to spiffe id %q", spiffeID)

	template := x509.Certificate{
		Subject: pkix.Name{
			CommonName: spiffeID.String(),
		},
		URIs:      []*url.URL{spiffeID},
		NotBefore: time.Now().Add(-10 * time.Minute),
		NotAfter:  time.Now().AddDate(10, 0, 0),

		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  false,
		BasicConstraintsValid: true,
	}

	cert, privateKey, err := s.signer.CreateCertificate(ctx, template)
	if err != nil {
		klog.Warningf("error building certificate: %v", err)
		return status.Errorf(codes.Internal, "error building certificate")
	}

	caCertificates, err := s.signer.GetCACertificates(ctx)
	if err != nil {
		klog.Warningf("error getting ca bundle: %v", err)
		return status.Errorf(codes.Internal, "error getting ca bundle")
	}
	var caCertificateBytes bytes.Buffer
	for _, caCert := range caCertificates {
		if _, err := caCertificateBytes.Write(caCert.Raw); err != nil {
			return status.Errorf(codes.Internal, "error encoding ca bundle")
		}
	}
	// caCertificateBytes, err := certs.EncodeCertificates(caCertificates)
	// if err != nil {
	// 	klog.Warningf("error encoding ca bundle: %v", err)
	// 	return status.Errorf(codes.Internal, "error encoding ca bundle")
	// }

	// certBytes, err := x509svid..EncodeCertificate(cert)
	// if err != nil {
	// 	klog.Warningf("error encoding certificate: %v", err)
	// 	return status.Errorf(codes.Internal, "error encoding certificate")
	// }

	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		klog.Warningf("error encoding key: %v", err)
		return status.Errorf(codes.Internal, "error encoding key")
	}

	svid := &workload.X509SVID{}
	svid.SpiffeId = s.trustDomain.String()
	svid.Bundle = caCertificateBytes.Bytes()
	svid.X509Svid = cert.Raw
	svid.X509SvidKey = privateKeyBytes

	response := &workload.X509SVIDResponse{}
	response.Svids = append(response.Svids, svid)
	stream.Send(response)

	for {
		time.Sleep(1 * time.Minute)
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
}

func (s *SPIREServer) FetchX509Bundles(req *workload.X509BundlesRequest, stream workload.SpiffeWorkloadAPI_FetchX509BundlesServer) error {
	klog.Infof("req %v", prototext.Format(req))
	return fmt.Errorf("FetchX509Bundles not implemented")
}
func (s *SPIREServer) FetchJWTSVID(ctx context.Context, req *workload.JWTSVIDRequest) (*workload.JWTSVIDResponse, error) {
	klog.Infof("req %v", prototext.Format(req))
	return nil, fmt.Errorf("FetchJWTSVID not implemented")
}
func (s *SPIREServer) FetchJWTBundles(req *workload.JWTBundlesRequest, stream workload.SpiffeWorkloadAPI_FetchJWTBundlesServer) error {
	klog.Infof("req %v", prototext.Format(req))
	return fmt.Errorf("FetchJWTBundles not implemented")
}
func (s *SPIREServer) ValidateJWTSVID(ctx context.Context, req *workload.ValidateJWTSVIDRequest) (*workload.ValidateJWTSVIDResponse, error) {
	klog.Infof("req %v", prototext.Format(req))
	return nil, fmt.Errorf("ValidateJWTSVID not implemented")
}

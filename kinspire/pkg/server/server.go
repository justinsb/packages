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

	v1 "github.com/justinsb/packages/kinspire/pb/v1"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"golang.org/x/exp/maps"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/prototext"
	"k8s.io/client-go/kubernetes"
	authenticationv1 "k8s.io/client-go/kubernetes/typed/authentication/v1"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type SPIREServer struct {
	authenticationClient authenticationv1.AuthenticationV1Interface
	kubeClient           client.Client
	tokenClient          corev1.CoreV1Interface
	signer               *LocalSigner
	trustDomain          *url.URL
	workload.UnimplementedSpiffeWorkloadAPIServer
	v1.UnimplementedKinspireServer
}

func NewSPIREServer(kubeClient client.Client, typedClient kubernetes.Interface, signer *LocalSigner, trustDomain *url.URL) (*SPIREServer, error) {
	authenticationClient := typedClient.AuthenticationV1()
	tokenClient := typedClient.CoreV1()

	return &SPIREServer{
		kubeClient:           kubeClient,
		authenticationClient: authenticationClient,
		tokenClient:          tokenClient,
		signer:               signer,
		trustDomain:          trustDomain,
	}, nil
}

func (s *SPIREServer) RegisterGRPC(grpcServer *grpc.Server) {
	workload.RegisterSpiffeWorkloadAPIServer(grpcServer, s)
	v1.RegisterKinspireServer(grpcServer, s)
}

type Identity interface {
	SPIFFEID() url.URL
}

type KubernetesServiceAccountIdentity struct {
	spiffeID  url.URL
	namespace string
	name      string
}

var _ Identity = &KubernetesServiceAccountIdentity{}

func (i *KubernetesServiceAccountIdentity) SPIFFEID() url.URL {
	return i.spiffeID
}

func (i *KubernetesServiceAccountIdentity) GetName() string {
	return i.name
}

func (i *KubernetesServiceAccountIdentity) GetNamespace() string {
	return i.namespace
}

func (s *SPIREServer) authenticate(ctx context.Context) (Identity, error) {
	var authorization []string
	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		authorization = md.Get("authorization")
	}

	if len(authorization) > 1 {
		return nil, status.Errorf(codes.InvalidArgument, "multiple authorization headers found")
	}

	if len(authorization) == 0 {
		return nil, status.Errorf(codes.Unauthenticated, "authorization not found")
	}

	auth, err := s.verifyKubernetesServiceAccountToken(ctx, authorization[0])
	if err != nil {
		klog.Warningf("error verifying token: %v", err)
		return nil, status.Errorf(codes.Internal, "error verifying token")
	}
	if auth == nil {
		return nil, status.Errorf(codes.Unauthenticated, "authentication failed")
	}

	klog.Infof("auth %v", auth)

	expectedAudiences := map[string]bool{
		"kubernetes.svc.default":                       true, // kOps (?))
		"https://kubernetes.default.svc.cluster.local": true, // kind
	}
	hasAudience := false
	for _, aud := range auth.Audiences {
		if expectedAudiences[aud] {
			hasAudience = true
		}
	}

	if !hasAudience {
		klog.Warningf("user did not have expected audience %v: %+v", maps.Keys(expectedAudiences), auth)
		return nil, status.Errorf(codes.PermissionDenied, "permission denied")
	}

	var identity Identity
	userTokens := strings.Split(auth.UserName, ":")
	if len(userTokens) == 4 && userTokens[0] == "system" && userTokens[1] == "serviceaccount" {
		ns := userTokens[2]
		name := userTokens[3]

		identity = &KubernetesServiceAccountIdentity{
			spiffeID:  *s.trustDomain.JoinPath("ns", ns, "sa", name),
			namespace: ns,
			name:      name,
		}
	}

	if identity == nil {
		klog.Warningf("cannot map user %+v to spiffe", auth)
		return nil, status.Errorf(codes.PermissionDenied, "permission denied")
	}

	return identity, nil
}

func (s *SPIREServer) FetchX509SVID(req *workload.X509SVIDRequest, stream workload.SpiffeWorkloadAPI_FetchX509SVIDServer) error {
	ctx := stream.Context()
	klog.Infof("FetchX509SVID: req=%v", prototext.Format(req))

	identity, err := s.authenticate(ctx)
	if err != nil {
		return err
	}

	spiffeID := identity.SPIFFEID()

	klog.Infof("mapped to spiffe id %q", spiffeID.String())

	template := x509.Certificate{
		Subject: pkix.Name{
			CommonName: spiffeID.String(),
		},
		URIs:      []*url.URL{&spiffeID},
		NotBefore: time.Now().Add(-10 * time.Minute),
		NotAfter:  time.Now().AddDate(10, 0, 0),

		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
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

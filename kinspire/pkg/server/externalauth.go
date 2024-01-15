package server

import (
	"context"
	"fmt"

	v1 "github.com/justinsb/packages/kinspire/pb/v1"
	"google.golang.org/protobuf/encoding/prototext"
	"k8s.io/klog/v2"
)

type ExternalAuthPlugin interface {
}

func (s *SPIREServer) GetExternalAuth(ctx context.Context, req *v1.GetExternalAuthRequest) (*v1.GetExternalAuthReply, error) {
	klog.Infof("GetExternalAuth: req=%v", prototext.Format(req))

	identity, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	spiffeID := identity.SPIFFEID()

	klog.Infof("mapped to spiffe id %q", spiffeID.String())

	switch req.GetTarget() {
	case "amazonaws.com":
		aws := &externalAuthAWS{kubeClient: s.kubeClient, tokenClient: s.tokenClient}
		return aws.GetExternalAuth(ctx, req, identity)

	default:
		return nil, fmt.Errorf("unknown target %q", req.GetTarget())
	}
}

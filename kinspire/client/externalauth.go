package client

import (
	"context"

	v1 "github.com/justinsb/packages/kinspire/pb/v1"
)

// type ExternalAuth struct {
// 	Token *oauth2.Token
// }

func (s *spiffe) GetExternalAuth(ctx context.Context, req *v1.GetExternalAuthRequest) (*v1.GetExternalAuthReply, error) {
	return s.kinspire.GetExternalAuth(ctx, req)
}

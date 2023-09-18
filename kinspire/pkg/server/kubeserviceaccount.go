package server

import (
	"context"
	"fmt"

	authenticationv1 "k8s.io/api/authentication/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"
)

type AuthInfo struct {
	UserName string
	UserUID  string

	PodName string
	PodUID  string

	Audiences []string
}

func (s *SPIREServer) verifyKubernetesServiceAccountToken(ctx context.Context, token string) (*AuthInfo, error) {
	req := &authenticationv1.TokenReview{}
	req.Spec.Token = token
	req.Spec.Audiences = []string{}
	result, err := s.authenticationClient.TokenReviews().Create(ctx, req, v1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("verifying token: %w", err)
	}
	if !result.Status.Authenticated {
		return nil, nil
	}
	klog.Infof("verification result is %+v", result.Status)
	info := &AuthInfo{}
	info.UserName = result.Status.User.Username
	info.UserUID = result.Status.User.UID
	info.Audiences = result.Status.Audiences

	for k, v := range result.Status.User.Extra {
		switch k {
		case "authentication.kubernetes.io/pod-uid":
			info.PodUID = v.String()
		case "authentication.kubernetes.io/pod-name":
			info.PodName = v.String()
		}
	}

	return info, nil
}

// type jwtHeader struct {
// 	Algorithm string `json:"alg,omitempty"`
// 	KeyType   string `json:"typ,omitempty"`
// 	KeyID     string `json:"kid,omitempty"`
// }

// type jwtPayload struct {
// 	ExpiresAt  int64             `json:"exp,omitempty"`
// 	IssuedAt   int64             `json:"iat,omitempty"`
// 	Issuer     string            `json:"iss,omitempty"`
// 	Audience   []string          `json:"aud,omitempty"`
// 	Kubernetes jwtKubernetesData `json:"kubernetes.io,omitempty"`
// }
// type jwtKubernetesData struct {
// 	Namespace      string                `json:"namespace,omitempty"`
// 	Pod            jwtPodData            `json:"pod,omitempty"`
// 	ServiceAccount jwtServiceAccountData `json:"serviceaccount,omitempty"`
// }

// type jwtPodData struct {
// 	Name string `json:"name,omitempty"`
// 	UID  string `json:"uid,omitempty"`
// }

// type jwtServiceAccountData struct {
// 	Name string `json:"name,omitempty"`
// 	UID  string `json:"uid,omitempty"`
// }

// type serviceAccountToken struct {
// 	Header  jwtHeader
// 	Payload jwtPayload
// }

// func parseServiceAccountData(ctx context.Context, tokenString string) (*jwtPayload, error) {
// 	parts := strings.Split(tokenString, ".")
// 	if len(parts) != 3 {
// 		return nil, fmt.Errorf("corrupt JWT (got %d parts)", len(parts))
// 	}

// 	token := &serviceAccountToken{}

// 	for i, part := range parts {
// 		b, err := base64.RawURLEncoding.DecodeString(part)
// 		if err != nil {
// 			return nil, fmt.Errorf("corrupt JWT (invalid base64)")
// 		}
// 		switch i {
// 		case 0:
// 			if err := json.Unmarshal(b, &token.Header); err != nil {
// 				return nil, fmt.Errorf("corrupt JWT (invalid header): %w", err)
// 			}

// 		case 1:
// 			if err := json.Unmarshal(b, &token.Payload); err != nil {
// 				return nil, fmt.Errorf("corrupt JWT (invalid payload): %w", err)
// 			}
// 		}
// 	}
// }

// func verifyToken(tokenString string, token *serviceAccountToken) (bool, error) {
// 	if token.Header.KeyID == "" || token.Header.KeyType != "JWT" {
// 		klog.Infof("keyid not set / not jwt")
// 		return false, nil
// 	}

// 	if token.Payload.Issuer != p.oidcConfiguration.Issuer {
// 		// Not issued by this provider
// 		klog.Infof("issuer does not match")
// 		return false, nil
// 	}

// 	if token.Payload.Audience != p.audience {
// 		// Issued by this provider, but not intended for us
// 		klog.Info("audience does not match")
// 		return false, nil
// 	}

// 	timeNow := time.Now().Unix()
// 	if timeNow > token.Payload.ExpiresAt {
// 		// token has expired
// 		klog.Infof("token has expired")
// 		return false, nil
// 	}
// 	if timeNow < token.Payload.IssuedAt {
// 		// token is not yet valid
// 		klog.Infof("token issuedAt time not yet reached")
// 		return false, nil
// 	}

// 	if p.parsedKeySet == nil {
// 		// TODO: Invalidation
// 		ctx := context.Background()
// 		keySet, err := p.getKeyset(ctx, p.oidcConfiguration)
// 		if err != nil {
// 			return nil, fmt.Errorf("contacting auth provider for jwks: %w", err)
// 		}
// 		p.parsedKeySet = keySet
// 	}

// 	keyset := p.parsedKeySet
// 	key := keyset.Keys[token.Header.KeyID]
// 	if key == nil {
// 		klog.Infof("no key with keyid %q", token.Header.KeyID)
// 		return false, nil
// 	}

// 	switch token.Header.Algorithm {
// 	case "RS256":
// 		rsaPublicKey, ok := key.PublicKey.(*rsa.PublicKey)
// 		if !ok {
// 			klog.Infof("token algorithm was %q, but key type was %T", token.Header.Algorithm, key.PublicKey)
// 			return false, nil
// 		}
// 		if !verifyRSAToken(tokenString, token, rsaPublicKey) {
// 			klog.Infof("token signature was not valid")
// 			return false, nil
// 		}
// 		return true, nil

// 	default:
// 		// Note: don't support every algorithm, e.g. plaintext
// 		klog.Infof("token algorithm %q not supported", token.Header.Algorithm)
// 		return false, nil
// 	}

// }

// func verifyRSAToken(tokenString string, token *serviceAccountToken, key *rsa.PublicKey) bool {
// 	components := strings.Split(tokenString, ".")
// 	if len(components) != 3 {
// 		return false
// 	}
// 	sig, err := base64.RawURLEncoding.DecodeString(components[2])
// 	if err != nil {
// 		return false
// 	}

// 	data := []byte(components[0] + "." + components[1])
// 	hashed := sha256.Sum256(data)

// 	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, hashed[:], sig); err != nil {
// 		return false
// 	}

// 	return true
// }

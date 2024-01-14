package client

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	pb "github.com/justinsb/packages/kinspire/pb/v1"
)

func GetAWSCredentials() (aws.CredentialsProvider, error) {
	// TODO: Should we pre-fetch credentials?
	p := &awsCredentialsProvider{}
	// TODO: options?
	cachedCredentials := aws.NewCredentialsCache(p)
	return cachedCredentials, nil
}

type awsCredentialsProvider struct {
}

var _ aws.CredentialsProvider = &awsCredentialsProvider{}

// Retrieve implements aws.CredentialsProvider
func (p *awsCredentialsProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	req := &pb.GetExternalAuthRequest{
		Target: "amazonaws.com",
	}
	var creds aws.Credentials
	response, err := SPIFFE.GetExternalAuth(ctx, req)
	if err != nil {
		return creds, err
	}
	creds.AccessKeyID = response.GetAwsAuth().GetAccessKeyId()
	if creds.AccessKeyID == "" {
		return creds, fmt.Errorf("empty credentials received from server")
	}
	creds.SecretAccessKey = response.GetAwsAuth().GetSecretAccessKey()
	creds.SessionToken = response.GetAwsAuth().GetSessionToken()
	if expirationTime := response.GetAwsAuth().ExpirationTime; expirationTime != nil {
		creds.Expires = expirationTime.AsTime()
	}
	return creds, nil
}

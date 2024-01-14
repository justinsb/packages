package server

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/justinsb/packages/kinspire/api"
	v1 "github.com/justinsb/packages/kinspire/pb/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
	authenticationv1 "k8s.io/api/authentication/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type externalAuthAWS struct {
	tokenClient corev1.CoreV1Interface
	kubeClient  client.Client
}

func (a *externalAuthAWS) GetExternalAuth(ctx context.Context, req *v1.GetExternalAuthRequest, identity Identity) (*v1.GetExternalAuthReply, error) {
	log := klog.FromContext(ctx)

	ksa := identity.(*KubernetesServiceAccountIdentity)

	ksaID := types.NamespacedName{
		Namespace: ksa.GetNamespace(),
		Name:      ksa.GetName(),
	}
	awsAuthID := ksaID // Convention: same name
	var awsAuth api.AWSAuth
	if err := a.kubeClient.Get(ctx, awsAuthID, &awsAuth); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("no AWS auth for serviceAccount %v", awsAuthID)
		}
		return nil, fmt.Errorf("getting AWSAuth %v: %w", awsAuthID, err)
	}

	role := awsAuth.Spec.Role
	if role == "" {
		return nil, fmt.Errorf("role not specified in AWSAuth %v", awsAuthID)
	}

	roleARN := role // TODO: Default the account ID

	tokenRequest := &authenticationv1.TokenRequest{}
	tokenRequest.Spec.Audiences = []string{req.Target}
	expirationSeconds := int64(86400)
	tokenRequest.Spec.ExpirationSeconds = &expirationSeconds
	// TODO: Gives an error?
	// tokenRequest.Spec.BoundObjectRef = &authenticationv1.BoundObjectReference{
	// 	Kind:       "ServiceAccount",
	// 	APIVersion: "v1",
	// 	Name:       ksa.GetName(),
	// }
	tokenRequest.SetNamespace(ksa.GetNamespace())

	log.Info("getting serviceaccount token for kubernetes serviceaccount", "namespace", ksa.GetNamespace(), "name", ksa.GetName())
	result, err := a.tokenClient.ServiceAccounts(ksa.GetNamespace()).CreateToken(ctx, ksa.GetName(), tokenRequest, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("creating token: %w", err)
	}

	token := result.Status.Token
	// expirationTimestamp := result.Status.ExpirationTimestamp.Time

	awsConfig, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}
	// TODO: Which region?
	awsConfig.Region = "us-east-2"
	stsClient := sts.NewFromConfig(awsConfig)

	roleSessionName := ksa.GetName() + "@" + ksa.GetNamespace()

	stsRequest := sts.AssumeRoleWithWebIdentityInput{
		WebIdentityToken: &token,
		RoleArn:          &roleARN,
		RoleSessionName:  &roleSessionName,
	}
	stsResponse, err := stsClient.AssumeRoleWithWebIdentity(ctx, &stsRequest)
	if err != nil {
		return nil, fmt.Errorf("getting STS identity: %w", err)
	}

	// log.Info("got AWS credentials", "accessKeyId", aws.ToString(stsResponse.Credentials.AccessKeyId))
	response := &v1.GetExternalAuthReply{
		AwsAuth: &v1.AWSAuthentication{
			AccessKeyId:     aws.ToString(stsResponse.Credentials.AccessKeyId),
			SecretAccessKey: aws.ToString(stsResponse.Credentials.SecretAccessKey),
			SessionToken:    aws.ToString(stsResponse.Credentials.SessionToken),
		},
	}

	if stsResponse.Credentials.Expiration != nil {
		response.AwsAuth.ExpirationTime = timestamppb.New(*stsResponse.Credentials.Expiration)
	}

	return response, nil
}

package authenticator

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
)

type CognitoAuth struct {
	poolId string
	client *cognitoidentityprovider.Client
}

const MAX_GROUPS_LIMIT = 60

type InitializeParams struct {
	PoolId string
	Config aws.Config
}

func (c *CognitoAuth) Initialize(params InitializeParams) {
	c.poolId = params.PoolId
	c.client = cognitoidentityprovider.NewFromConfig(params.Config)
}

func (c *CognitoAuth) AuthenticateUser(ctx context.Context, token string) (*cognitoidentityprovider.GetUserOutput, error) {
	return c.client.GetUser(ctx, &cognitoidentityprovider.GetUserInput{
		AccessToken: &token,
	})
}

func (c *CognitoAuth) GetUserGroup(ctx context.Context, userName string, limit int, nextToken string) (*cognitoidentityprovider.AdminListGroupsForUserOutput, error) {
	l := int32(limit)
	if nextToken == "" {
		return c.client.AdminListGroupsForUser(ctx, &cognitoidentityprovider.AdminListGroupsForUserInput{
			UserPoolId: &c.poolId,
			Username:   &userName,
			Limit:      &l,
		})
	} else {
		return c.client.AdminListGroupsForUser(ctx, &cognitoidentityprovider.AdminListGroupsForUserInput{
			UserPoolId: &c.poolId,
			Username:   &userName,
			Limit:      &l,
			NextToken:  &nextToken,
		})
	}

}

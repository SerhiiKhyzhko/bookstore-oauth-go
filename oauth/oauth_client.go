package oauth

import (
	"time"

	"github.com/go-resty/resty/v2"
)

type OAuthClient struct {
	client *resty.Client
}

func NewOAuthClient(baseUrl string, timeout time.Duration) *OAuthClient {
    return &OAuthClient{
        client: resty.New().SetTimeout(timeout).SetBaseURL(baseUrl),
    }
}

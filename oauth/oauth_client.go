package oauth

import (
	"time"

	"github.com/go-resty/resty/v2"
)

var (
	usersRestClient *resty.Client
)

func Init(restyBaseUrl string) {
	usersRestClient = resty.New().SetTimeout(150 * time.Millisecond).SetBaseURL(restyBaseUrl)
}

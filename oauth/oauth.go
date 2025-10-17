package oauth

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"bookstore-oauth-go/errors"

	"github.com/go-resty/resty/v2"
)

const (
	headerXPublic   = "X_Public"
	headerXClientId = "X-Client-Id"
	headerXCallerId = "X-Caller-Id"
	
	paramAccessToken = "access_token"
)

var usersRestClient = resty.New().SetTimeout(150 * time.Millisecond)

type accessToken struct {
	Id string `json:"id"`
	UserId int64 `json:"user_id"`
	ClientId int64 `json:"client_id"`
}

func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}
	return request.Header.Get(headerXPublic) == "true"
}

func GetCallerId(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	callerId, err := strconv.ParseInt(request.Header.Get(headerXCallerId), 10, 64)
	if err != nil {
		return 0
	}
	return callerId
}

func GetClientId(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	clientId, err := strconv.ParseInt(request.Header.Get(headerXClientId), 10, 64)
	if err != nil {
		return 0
	}
	return clientId
}

func AutenticationRequest(request *http.Request) *errors.RestErr{
	if request == nil {
		return nil
	}

	cleanRequest(request)

	accessTokenId := strings.TrimSpace(request.URL.Query().Get(paramAccessToken))
	if accessTokenId == "" {
		return nil
	}
	at, err := getAccessToken(accessTokenId)
	if err != nil {
		if err.Status == http.StatusNotFound {
			return nil
		}
		return err
	}

	request.Header.Add(headerXClientId, fmt.Sprintf("%v", at.ClientId))
	request.Header.Add(headerXCallerId, fmt.Sprintf("%v", at.UserId))

	return nil
}

func cleanRequest(request *http.Request){
	if request == nil {
		return
	}
	request.Header.Del(headerXClientId)
	request.Header.Del(headerXCallerId)
}

func getAccessToken(accessTokenId string) (*accessToken, *errors.RestErr) {
	var responseErr errors.RestErr
	var at accessToken

	response, err := usersRestClient.R().
	SetResult(&at).
	SetError(&responseErr).
	Post(fmt.Sprintf("/oauth/access_token/%s", accessTokenId))


	if err != nil {
		return nil, errors.NewInternalServerError(err.Error())//posibly network or timeout error
	}

	if response.IsError() {
		if responseErr.Status == 404 {
			return  nil, errors.NewNotFoundError(responseErr.Message)
		} else {
			return nil, errors.NewInternalServerError(responseErr.Message)
		}
	}

	return &at, nil
}

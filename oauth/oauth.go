package oauth

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/SerhiiKhyzhko/bookstore-oauth-go/oauthErrors"
	"github.com/SerhiiKhyzhko/bookstore_utils-go/rest_errors"
)

const (
	headerXPublic   = "X-Public"
	headerXClientId = "X-Client-Id"
	headerXCallerId = "X-Caller-Id"

	paramAccessToken = "access_token"
)

type accessToken struct {
	Id       string `json:"id"`
	UserId   int64  `json:"user_id"`
	ClientId int64  `json:"client_id"`
}

func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}
	return request.Header.Get(headerXPublic) == "true"
}

func GetCallerId(request *http.Request) (int64, bool) {
	if request == nil {
		return 0, false
	}
	callerId, err := strconv.ParseInt(request.Header.Get(headerXCallerId), 10, 64)
	if err != nil {
		return 0, false
	}
	return callerId, true
}

func GetClientId(request *http.Request) (int64, bool) {
	if request == nil {
		return 0, false
	}
	clientId, err := strconv.ParseInt(request.Header.Get(headerXClientId), 10, 64)
	if err != nil {
		return 0, false
	}
	return clientId, true
}

func AuthenticationRequest(request *http.Request) error {
	if request == nil {
		return nil
	}

	cleanRequest(request)

	accessTokenId := strings.TrimSpace(request.URL.Query().Get(paramAccessToken))
	if accessTokenId == "" {
		return oauthErrors.BadRequestErr
	}
	at, err := getAccessToken(accessTokenId)
	if err != nil {
		if err.Status() == http.StatusNotFound {
			return oauthErrors.TokenNotFoundErr 
		}
		return oauthErrors.NewCustomInternalServerError(err.Error())
	}

	request.Header.Add(headerXClientId, fmt.Sprintf("%v", at.ClientId))
	request.Header.Add(headerXCallerId, fmt.Sprintf("%v", at.UserId))

	return nil
}

func cleanRequest(request *http.Request) {
	if request == nil {
		return
	}
	request.Header.Del(headerXClientId)
	request.Header.Del(headerXCallerId)
}

func getAccessToken(accessTokenId string) (*accessToken, rest_errors.RestErr) {
	var at accessToken

	response, err := usersRestClient.R().
		SetResult(&at).
		Get(fmt.Sprintf("/oauth/access_token/%s", accessTokenId))

	if err != nil {
		return nil, rest_errors.NewInternalServerError(err.Error(), err) //posibly network or timeout error
	}

	if response.IsError() {
		responseErr, err := rest_errors.NewRestErrorFromBytes(response.Body())
		if err != nil {
			return nil, rest_errors.NewInternalServerError(err.Error(), err)
		}
		if responseErr.Status() == http.StatusNotFound {
			return nil, rest_errors.NewNotFoundError(responseErr.Message())
		} else {
			return nil, rest_errors.NewInternalServerError(responseErr.Message(), errors.New(responseErr.Error()))
		}
	}

	return &at, nil
}

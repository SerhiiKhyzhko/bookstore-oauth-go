package oauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"

	//"strings"
	"testing"

	"github.com/SerhiiKhyzhko/bookstore-oauth-go/oauthErrors"
	"github.com/SerhiiKhyzhko/bookstore_utils-go/rest_errors"
	"github.com/go-resty/resty/v2"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
)

const (
	// Визначимо константу для базового URL, щоб уникнути помилок
	mockAPIBaseURL = "http://localhost:8080"
)

// setUp тепер встановлює BaseURL
func setUp() *OAuthClient {
	mockedClient := resty.New().SetBaseURL(mockAPIBaseURL) // ВАЖЛИВО: Встановлюємо BaseURL
	httpmock.ActivateNonDefault(mockedClient.GetClient())
	return &OAuthClient{
		client: mockedClient,
	}
}

func tearDown() {
	httpmock.DeactivateAndReset()
}

func TestConstants(t *testing.T) {
	assert.EqualValues(t, "X-Public", headerXPublic)
	assert.EqualValues(t, "X-Client-Id", headerXClientId)
	assert.EqualValues(t, "X-Caller-Id", headerXCallerId)
	assert.EqualValues(t, "access_token", paramAccessToken)
}

func TestIsPublic(t *testing.T) {
	client := OAuthClient{} // No state needed for this method

	t.Run("NilRequest", func(t *testing.T) {
		assert.True(t, client.IsPublic(nil))
	})

	t.Run("PublicRequest", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(headerXPublic, "true")
		assert.True(t, client.IsPublic(req))
	})

	t.Run("NonPublicRequest", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(headerXPublic, "false")
		assert.False(t, client.IsPublic(req))
	})

	t.Run("NoHeaderRequest", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		assert.False(t, client.IsPublic(req))
	})
}

func TestGetId(t *testing.T) {
	client := OAuthClient{} // No state needed for this method

	t.Run("GetCallerId", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(headerXCallerId, "123")
		id, ok := client.GetCallerId(req)
		assert.True(t, ok)
		assert.EqualValues(t, 123, id)
	})

	t.Run("GetClientId", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(headerXClientId, "456")
		id, ok := client.GetClientId(req)
		assert.True(t, ok)
		assert.EqualValues(t, 456, id)
	})

	t.Run("InvalidId", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(headerXCallerId, "abc")
		id, ok := client.GetCallerId(req)
		assert.False(t, ok)
		assert.EqualValues(t, 0, id)
	})

	t.Run("NilRequest", func(t *testing.T) {
		id, ok := client.GetCallerId(nil)
		assert.False(t, ok)
		assert.EqualValues(t, 0, id)
	})
}

func TestCleanRequest(t *testing.T) {
	t.Run("CleansHeaders", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(headerXCallerId, "1")
		req.Header.Set(headerXClientId, "2")
		req.Header.Set("X-Something-Else", "3")

		cleanRequest(req)

		assert.Empty(t, req.Header.Get(headerXCallerId))
		assert.Empty(t, req.Header.Get(headerXClientId))
		assert.Equal(t, "3", req.Header.Get("X-Something-Else"))
	})

	t.Run("NilRequest", func(t *testing.T) {
		// Should not panic
		cleanRequest(nil)
	})
}

func TestAuthenticationRequest(t *testing.T) {
	oauthClient := setUp()
	defer tearDown()

	t.Run("NilRequest", func(t *testing.T) {
		err := oauthClient.AuthenticationRequest(nil)
		assert.Nil(t, err)
	})

	t.Run("NoAccessToken", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		err := oauthClient.AuthenticationRequest(req)
		assert.NotNil(t, err)
		assert.ErrorIs(t, err, oauthErrors.BadRequestErr)
	})

	t.Run("TokenNotFound", func(t *testing.T) {
		// Створюємо фейкову відповідь від API, яку поверне getAccessToken
		restErr := rest_errors.NewNotFoundError("token not found")
		jsonBytes, _ := json.Marshal(restErr)
		url := fmt.Sprintf("%s/oauth/access_token/invalid-token", mockAPIBaseURL)
		httpmock.RegisterResponder("GET", url, httpmock.NewBytesResponder(404, jsonBytes))

		req := httptest.NewRequest(http.MethodGet, "/?access_token=invalid-token", nil)
		err := oauthClient.AuthenticationRequest(req)

		assert.NotNil(t, err)
		// ВИПРАВЛЕНО: Використовуємо assert.ErrorIs для перевірки обгорнутих помилок
		assert.ErrorIs(t, err, oauthErrors.TokenNotFoundErr)
	})

	t.Run("InternalServerErrorFromRemote", func(t *testing.T) {
		restErr := rest_errors.NewInternalServerError("db error", nil)
		jsonBytes, _ := json.Marshal(restErr)
		url := fmt.Sprintf("%s/oauth/access_token/internal-error-token", mockAPIBaseURL)
		httpmock.RegisterResponder("GET", url, httpmock.NewBytesResponder(500, jsonBytes))

		req := httptest.NewRequest(http.MethodGet, "/?access_token=internal-error-token", nil)
		err := oauthClient.AuthenticationRequest(req)

		assert.NotNil(t, err)
		// ВИПРАВЛЕНО: Перевіряємо, що в ланцюжку помилок є InternalServerErr
		assert.ErrorIs(t, err, oauthErrors.InternalServerErr)
	})

	t.Run("Success", func(t *testing.T) {
		// КЛЮЧОВЕ ВИПРАВЛЕННЯ: Використовуємо повний URL
		url := fmt.Sprintf("%s/oauth/access_token/valid-token", mockAPIBaseURL)
		httpmock.RegisterResponder("GET", url, httpmock.NewJsonResponderOrPanic(200, map[string]interface{}{
            "id":        "the-token",
            "user_id":   123,
            "client_id": 456,
        }),
    )

		req := httptest.NewRequest(http.MethodGet, "/?access_token=valid-token", nil)
		req.Header.Set(headerXCallerId, "old-caller")
		req.Header.Set(headerXClientId, "old-client")

		err := oauthClient.AuthenticationRequest(req)

		// Тепер ці асерти мають пройти, бо `err` буде `nil`
		assert.Nil(t, err)
		assert.Equal(t, "123", req.Header.Get(headerXCallerId))
		assert.Equal(t, "456", req.Header.Get(headerXClientId))
	})
}

func TestGetAccessToken(t *testing.T) {
	oauthClient := setUp()
	defer tearDown()

	t.Run("NetworkError", func(t *testing.T) {
		url := fmt.Sprintf("%s/oauth/access_token/network-error", mockAPIBaseURL)
		httpmock.RegisterResponder("GET", url, httpmock.NewErrorResponder(errors.New("timeout")))

		at, err := oauthClient.getAccessToken("network-error")

		assert.Nil(t, at)
		assert.NotNil(t, err)
		// ВИПРАВЛЕНО: Перевіряємо обгорнуту помилку
		assert.ErrorIs(t, err, oauthErrors.InternalServerErr)
		assert.Contains(t, err.Error(), "timeout")
	})

	t.Run("NotFound", func(t *testing.T) {
		url := fmt.Sprintf("%s/oauth/access_token/not-found-token", mockAPIBaseURL)
		restErr := rest_errors.NewNotFoundError("token not found")
		jsonBytes, _ := json.Marshal(restErr)
		httpmock.RegisterResponder("GET", url, httpmock.NewBytesResponder(404, jsonBytes))

		at, err := oauthClient.getAccessToken("not-found-token")

		assert.Nil(t, at)
		assert.NotNil(t, err)
		// ВИПРАВЛЕНО: Перевіряємо обгорнуту помилку
		assert.ErrorIs(t, err, oauthErrors.TokenNotFoundErr)
	})

	t.Run("Success", func(t *testing.T) {
		url := fmt.Sprintf("%s/oauth/access_token/good-token", mockAPIBaseURL)
		httpmock.RegisterResponder("GET", url, httpmock.NewJsonResponderOrPanic(200, map[string]interface{}{
            "id":        "the-token",
            "user_id":   999,
            "client_id": 777,
        }),
    )

		at, err := oauthClient.getAccessToken("good-token")

		assert.NoError(t, err) // Успішний виклик повертає nil як помилку
		assert.NotNil(t, at)
		assert.Equal(t, "the-token", at.Id)
		assert.EqualValues(t, 999, at.UserId)
		assert.EqualValues(t, 777, at.ClientId)
	})
}

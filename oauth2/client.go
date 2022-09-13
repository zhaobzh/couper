package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/avenga/couper/config"
	"github.com/avenga/couper/config/request"
	"github.com/avenga/couper/eval"
)

// Client represents an OAuth2 client.
type Client struct {
	backend      http.RoundTripper
	asConfig     config.OAuth2AS
	clientConfig config.OAuth2Client
	grantType    string
}

func NewClient(grantType string, asConfig config.OAuth2AS, clientConfig config.OAuth2Client, backend http.RoundTripper) (*Client, error) {
	if teAuthMethod := clientConfig.GetTokenEndpointAuthMethod(); teAuthMethod != nil {
		if *teAuthMethod != "client_secret_basic" && *teAuthMethod != "client_secret_post" {
			return nil, fmt.Errorf("token_endpoint_auth_method %q not supported", *teAuthMethod)
		}
	}

	return &Client{
		backend,
		asConfig,
		clientConfig,
		grantType,
	}, nil
}

func (c *Client) requestToken(tokenReq *http.Request) ([]byte, int, error) {
	ctx, cancel := context.WithCancel(tokenReq.Context())
	defer cancel()

	tokenRes, err := c.backend.RoundTrip(tokenReq.WithContext(ctx))
	if err != nil {
		return nil, 0, err
	}
	defer tokenRes.Body.Close()

	tokenResBytes, err := io.ReadAll(tokenRes.Body)
	if err != nil {
		return nil, tokenRes.StatusCode, err
	}

	return tokenResBytes, tokenRes.StatusCode, nil
}

func (c *Client) newTokenRequest(ctx context.Context, formParams url.Values) (*http.Request, error) {
	tokenURL, err := c.asConfig.GetTokenEndpoint()
	if err != nil {
		return nil, err
	}

	outreq, err := http.NewRequest(http.MethodPost, tokenURL, nil)
	if err != nil {
		return nil, err
	}

	outreq.Header.Set("Accept", "application/json")
	outreq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	formParams.Set("grant_type", c.grantType)

	authenticateClient(c.clientConfig, &formParams, outreq)

	outCtx := context.WithValue(ctx, request.TokenRequest, "oauth2")

	eval.SetBody(outreq, []byte(formParams.Encode()))

	return outreq.WithContext(outCtx), nil
}

func authenticateClient(clientConfig config.OAuth2Client, formParams *url.Values, tokenReq *http.Request) {
	if !clientConfig.ClientAuthenticationRequired() {
		return
	}

	clientID := clientConfig.GetClientID()
	clientSecret := clientConfig.GetClientSecret()
	if authMethod := clientConfig.GetTokenEndpointAuthMethod(); authMethod == nil || *authMethod == "client_secret_basic" {
		tokenReq.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(clientSecret))
	} else if *authMethod == "client_secret_post" {
		formParams.Set("client_id", clientID)
		formParams.Set("client_secret", clientSecret)
	}
}

func (c *Client) GetTokenResponse(ctx context.Context, formParams url.Values) (map[string]interface{}, string, error) {
	tokenReq, err := c.newTokenRequest(ctx, formParams)
	if err != nil {
		return nil, "", err
	}

	tokenResponse, statusCode, err := c.requestToken(tokenReq)
	if err != nil {
		return nil, "", err
	}

	tokenResponseData, accessToken, err := parseTokenResponse(tokenResponse)
	if err != nil {
		return nil, "", err
	}

	if statusCode != http.StatusOK {
		e, _ := tokenResponseData["error"].(string)
		msg := fmt.Sprintf("error=%s", e)
		errorDescription, dExists := tokenResponseData["error_description"].(string)
		if dExists {
			msg += fmt.Sprintf(", error_description=%s", errorDescription)
		}
		errorURI, uExists := tokenResponseData["error_uri"].(string)
		if uExists {
			msg += fmt.Sprintf(", error_uri=%s", errorURI)
		}
		return nil, "", fmt.Errorf(msg)
	}

	return tokenResponseData, accessToken, nil
}

func parseTokenResponse(tokenResponse []byte) (map[string]interface{}, string, error) {
	var tokenResponseData map[string]interface{}

	err := json.Unmarshal(tokenResponse, &tokenResponseData)
	if err != nil {
		return nil, "", err
	}

	var accessToken string
	if t, ok := tokenResponseData["access_token"].(string); ok {
		accessToken = t
	} else {
		accessToken = ""
	}

	return tokenResponseData, accessToken, nil
}

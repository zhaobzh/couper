package lib

import (
	"fmt"

	pkce "github.com/jimlambrt/go-oauth-pkce-code-verifier"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
)

const (
	FnOAuthCodeVerifier    = "oauth_code_verifier"
	FnOAuthCodeChallenge   = "oauth_code_challenge"
	FnOAuthCsrfToken       = "oauth_csrf_token"
	FnOAuthHashedCsrfToken = "oauth_hashed_csrf_token"
	CodeVerifier           = "code_verifier"
	CCM_plain              = "plain"
	CCM_S256               = "S256"
)

func NewOAuthCodeVerifierFunction(verifier func() (*pkce.CodeVerifier, error)) function.Function {
	return function.New(&function.Spec{
		Params: []function.Parameter{},
		Type:   function.StaticReturnType(cty.String),
		Impl: func(args []cty.Value, _ cty.Type) (ret cty.Value, err error) {
			codeVerifier, err := verifier()
			if err != nil {
				return cty.StringVal(""), err
			}

			return cty.StringVal(codeVerifier.String()), nil
		},
	})
}

func NewOAuthCodeChallengeFunction(verifier func() (*pkce.CodeVerifier, error)) function.Function {
	return function.New(&function.Spec{
		Params: []function.Parameter{
			{
				Name: "code_challenge_method",
				Type: cty.String,
			},
		},
		Type: function.StaticReturnType(cty.String),
		Impl: func(args []cty.Value, _ cty.Type) (ret cty.Value, err error) {
			method := args[0].AsString()
			return createCodeChallenge(verifier, method)
		},
	})
}

func NewOAuthHashedCsrfTokenFunction(verifier func() (*pkce.CodeVerifier, error)) function.Function {
	return function.New(&function.Spec{
		Params: []function.Parameter{},
		Type:   function.StaticReturnType(cty.String),
		Impl: func(args []cty.Value, _ cty.Type) (ret cty.Value, err error) {
			return createCodeChallenge(verifier, CCM_S256)
		},
	})
}

func createCodeChallenge(verifier func() (*pkce.CodeVerifier, error), method string) (cty.Value, error) {
	codeVerifier, err := verifier()
	if err != nil {
		return cty.StringVal(""), err
	}

	switch method {
	case CCM_S256:
		return cty.StringVal(codeVerifier.CodeChallengeS256()), nil
	case CCM_plain:
		return cty.StringVal(codeVerifier.CodeChallengePlain()), nil
	default:
		return cty.StringVal(""), fmt.Errorf("unsupported code challenge method: %s", method)
	}
}

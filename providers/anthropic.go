package providers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kayushkin/aiauth"
)

const (
	AnthropicClientID     = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
	AnthropicAuthorizeURL = "https://claude.ai/oauth/authorize"
	AnthropicTokenURL     = "https://console.anthropic.com/v1/oauth/token"
	AnthropicRedirectURI  = "https://console.anthropic.com/oauth/code/callback"
	AnthropicScopes       = "org:create_api_key user:profile user:inference"
)

// Anthropic implements the aiauth.Provider interface.
type Anthropic struct{}

func NewAnthropic() *Anthropic { return &Anthropic{} }

func (a *Anthropic) ID() string { return "anthropic" }

func (a *Anthropic) Login(cb aiauth.LoginCallbacks) (*aiauth.Credential, error) {
	verifier, challenge, err := aiauth.GeneratePKCE()
	if err != nil {
		return nil, fmt.Errorf("PKCE generation failed: %w", err)
	}

	params := url.Values{
		"client_id":             {AnthropicClientID},
		"redirect_uri":         {AnthropicRedirectURI},
		"response_type":        {"code"},
		"scope":                {AnthropicScopes},
		"code_challenge":       {challenge},
		"code_challenge_method": {"S256"},
	}
	authURL := AnthropicAuthorizeURL + "?" + params.Encode()

	if cb.OnAuthURL != nil {
		if err := cb.OnAuthURL(authURL); err != nil {
			return nil, err
		}
	}

	if cb.OnPrompt == nil {
		return nil, fmt.Errorf("OnPrompt callback required")
	}

	code, err := cb.OnPrompt("Enter the authorization code from the browser:")
	if err != nil {
		return nil, err
	}
	code = strings.TrimSpace(code)

	return a.exchangeCode(code, verifier)
}

func (a *Anthropic) exchangeCode(code, verifier string) (*aiauth.Credential, error) {
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {AnthropicClientID},
		"code":          {code},
		"redirect_uri":  {AnthropicRedirectURI},
		"code_verifier": {verifier},
	}

	resp, err := http.PostForm(AnthropicTokenURL, data)
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("token exchange returned %d: %s", resp.StatusCode, body)
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	return &aiauth.Credential{
		Type:    "oauth",
		Provider: "anthropic",
		Access:  tokenResp.AccessToken,
		Refresh: tokenResp.RefreshToken,
		Expires: time.Now().UnixMilli() + tokenResp.ExpiresIn*1000,
	}, nil
}

func (a *Anthropic) RefreshToken(cred *aiauth.Credential) (*aiauth.Credential, error) {
	if cred.Refresh == "" {
		return nil, fmt.Errorf("no refresh token available")
	}

	data := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {AnthropicClientID},
		"refresh_token": {cred.Refresh},
	}

	resp, err := http.PostForm(AnthropicTokenURL, data)
	if err != nil {
		return nil, fmt.Errorf("token refresh failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("token refresh returned %d: %s", resp.StatusCode, body)
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse refresh response: %w", err)
	}

	refreshToken := tokenResp.RefreshToken
	if refreshToken == "" {
		refreshToken = cred.Refresh
	}

	return &aiauth.Credential{
		Type:     "oauth",
		Provider: "anthropic",
		Access:   tokenResp.AccessToken,
		Refresh:  refreshToken,
		Expires:  time.Now().UnixMilli() + tokenResp.ExpiresIn*1000,
		Email:    cred.Email,
	}, nil
}

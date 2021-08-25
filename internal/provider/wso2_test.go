package provider

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Tests

func TestWSO2Name(t *testing.T) {
	p := WSO2{}
	assert.Equal(t, "WSO2", p.Name())
}

func TestWSO2Setup(t *testing.T) {
	assert := assert.New(t)
	p := WSO2{}

	// Check validation
	err := p.Setup()
	if assert.Error(err) {
		assert.Equal("providers.WSO2.client-id, providers.WSO2.client-secret, providers.WSO2.grant-type must be set", err.Error())
	}

	// Check setup
	p = WSO2{
		ClientID:     "id",
		ClientSecret: "secret",
	}

	assert.Equal(&url.URL{
		Scheme: "https",
		Host:   p.TokenHost,
		Path:   "/oauth2/authorize",
	}, p.LoginURL)

	assert.Equal(&url.URL{
		Scheme: "https",
		Host:   p.TokenHost,
		Path:   "/token",
	}, p.TokenURL)

	assert.Equal(&url.URL{
		Scheme: "https",
		Host:   p.TokenHost,
		Path:   "/userinfo",
	}, p.UserURL)
}

func TestWSO2GetLoginURL(t *testing.T) {
	assert := assert.New(t)
	p := WSO2{
		ClientID:     "idtest",
		ClientSecret: "sectest",
		Scope:        "scopetest",
		LoginURL: &url.URL{
			Scheme: "https",
			Host:   "gw.api.cloud.sphereon.com",
			Path:   "/auth",
		},
	}

	// Check url
	uri, err := url.Parse(p.GetLoginURL("http://example.com/_oauth", "state"))
	assert.Nil(err)
	assert.Equal("https", uri.Scheme)
	assert.Equal(p.TokenHost, uri.Host)
	assert.Equal("/auth", uri.Path)

	// Check query string
	qs := uri.Query()
	expectedQs := url.Values{
		"client_id":     []string{"idtest"},
		"redirect_uri":  []string{"http://example.com/_oauth"},
		"response_type": []string{"code"},
		"scope":         []string{"scopetest"},
		//		"prompt":        []string{"consent select_account"},
		"state": []string{"state"},
	}
	assert.Equal(expectedQs, qs)
}

func TestWSO2ExchangeCode(t *testing.T) {
	assert := assert.New(t)

	// Setup server
	expected := url.Values{
		"client_id":     []string{"idtest"},
		"client_secret": []string{"sectest"},
		"code":          []string{"code"},
		"grant_type":    []string{"authorization_code"},
		"redirect_uri":  []string{"http://example.com/_oauth"},
	}
	server, serverURL := NewOAuthServer(t, map[string]string{
		"token": expected.Encode(),
	})
	defer server.Close()

	// Setup provider
	p := WSO2{
		ClientID:     "idtest",
		ClientSecret: "sectest",
		Scope:        "scopetest",
		//		Prompt:       "consent select_account",
		TokenURL: &url.URL{
			Scheme: serverURL.Scheme,
			Host:   serverURL.Host,
			Path:   "/token",
		},
	}

	token, err := p.ExchangeCode("http://example.com/_oauth", "code")
	assert.Nil(err)
	assert.Equal("123456789", token)
}

func TestWSO2GetUser(t *testing.T) {
	assert := assert.New(t)

	// Setup server
	server, serverURL := NewOAuthServer(t, nil)
	defer server.Close()

	// Setup provider
	p := WSO2{
		ClientID:     "idtest",
		ClientSecret: "sectest",
		Scope:        "scopetest",
		//Prompt:       "consent select_account",
		UserURL: &url.URL{
			Scheme: serverURL.Scheme,
			Host:   serverURL.Host,
			Path:   "/userinfo",
		},
	}

	user, err := p.GetUser("123456789")
	assert.Nil(err)

	assert.Equal("example@example.com", user.Email)
}

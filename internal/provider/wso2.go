package provider

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

// WSO2 provider
type WSO2 struct {
	AuthHost     string `long:"auth-host" env:"AUTH_HOST" description:"WSO identity server hostname"`
	TokenHost    string `long:"token-host" env:"TOKEN_HOST" description:"WSO2 gateway hostname"`
	ClientID     string `long:"client-id" env:"CLIENT_ID" description:"Client ID"`
	ClientSecret string `long:"client-secret" env:"CLIENT_SECRET" description:"Client Secret" json:"-"`
	GrantType    string `long:"grant-type" env:"GRANT_TYPE" description:"Grant type"`
	Scope        string `long:"scope" env:"SCOPE" description:"Scope key"`

	LoginURL *url.URL
	TokenURL *url.URL
	UserURL  *url.URL
}

// Name returns the name of the provider
func (wso2 *WSO2) Name() string {
	return "wso2"
}

// Setup performs validation and setup
func (wso2 *WSO2) Setup() error {
	logrus.Info("Setting up WSO2 provider %v", wso2)
	if wso2.ClientID == "" || wso2.ClientSecret == "" || wso2.GrantType == "" {
		return errors.New("providers.wso2.client-id, providers.wso2.client-secret, providers.wso2.grant-type must be set")
	}

	// Set static values
	wso2.LoginURL = &url.URL{
		Scheme: "https",
		Host:   wso2.TokenHost,
		Path:   "/oauth2/authorize",
	}
	wso2.TokenURL = &url.URL{
		Scheme: "https",
		Host:   wso2.TokenHost,
		Path:   "/token",
	}
	logrus.Infof("WSO2 TokenURL %v", wso2.TokenURL)
	wso2.UserURL = &url.URL{
		Scheme: "https",
		Host:   wso2.TokenHost,
		Path:   "/userinfo",
	}

	return nil
}

// GetLoginURL provides the login url for the given redirect uri and state
func (wso2 *WSO2) GetLoginURL(redirectURI, state string) string {

	q := url.Values{}
	q.Set("client_id", wso2.ClientID)
	q.Set("response_type", "code")
	q.Set("scope", wso2.Scope)
	q.Set("redirect_uri", redirectURI)
	q.Set("state", state)

	var u url.URL
	u = *wso2.LoginURL
	u.RawQuery = q.Encode()

	return u.String()
}

// ExchangeCode exchanges the given redirect uri and code for a token
func (wso2 *WSO2) ExchangeCode(redirectURI, code string) (string, error) {
	form := url.Values{}
	form.Set("grant_type", wso2.GrantType)
	form.Set("validity_period", "5400")
	logrus.Infof("Sending auth request to %s", wso2.TokenURL.String())
	req, err := http.NewRequest("POST", wso2.TokenURL.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}

	if wso2.GrantType == "client_credentials" {
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		form.Set("client_id", wso2.ClientID)
		form.Set("client_secret", wso2.ClientSecret)
	} else {
		return "", errors.New("Only grant type client_credentials supported for now.") // TODO
	}

	/*	if redirectURI != "" {
			form.Set("redirect_uri", redirectURI)
		}
		form.Set("code", code)

	*/
	//	logrus.WithField("request", req).WithField("form", form.Encode()).Debug("PostForm")

	response, err := http.PostForm(wso2.TokenURL.String(), form)
	if err != nil {
		logrus.Fatalf("Auth request failed: %v", err)
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		body, err := ioutil.ReadAll(response.Body)
		logrus.Fatalf("Auth request failed: %s\n%v", response.Status, string(body))
		return "", err
	}

	//	logrus.WithField("response", response).Debug("TokenURL response")

	var token token
	err = json.NewDecoder(response.Body).Decode(&token)
	if err != nil {
		logrus.Fatalf("Request decode failed: %v", err)
		return "", err
	}
	logrus.Infof("Token: %s", token.Token)
	return token.Token, nil
}

// GetUser uses the given token and returns a complete provider.User object
func (wso2 *WSO2) GetUser(token string) (User, error) {
	var user User

	client := &http.Client{}
	req, err := http.NewRequest("GET", wso2.UserURL.String(), nil)
	if err != nil {
		return user, err
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	res, err := client.Do(req)
	if err != nil {
		return user, err
	}

	defer res.Body.Close()
	err = json.NewDecoder(res.Body).Decode(&user)

	return user, err
}

func (wso2 *WSO2) IsCallbackSupported() bool {
	return wso2.GrantType == "authorization_code"
}

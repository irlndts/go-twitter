package twitter

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	twitterAPI = "https://api.twitter.com/1.1/"

	twitterOAuthURL             = "https://api.twitter.com/oauth"
	twitterRequestTokenURL      = twitterOAuthURL + "/request_token"
	twitterAccessTokenURL       = twitterOAuthURL + "/access_token"
	twitterOauthAuthenticateURL = twitterOAuthURL + "/authenticate"

	twitterStatusesUpdate = "https://api.twitter.com/1.1/statuses/update.json"

	contentType = "application/x-www-form-urlencoded;charset=UTF-8"
	userAgent   = "github.com/irlndts/go-twitter v0.1"
)

// Twitter ...
type Twitter struct {
	oauth OAuth
}

// Token ...
type Token struct {
	Type        string `json:"token_type"`
	AccessToken string `json:"access_token"`
}

// OAuth ...
type OAuth struct {
	ConsumerKey       string
	ConsumerSecret    string
	Version           string
	SignatureMethod   string
	Token             string
	TokenSecret       string
	CallbackConfirmed string

	AOAToken Token
}

// NewClient returns twitter client
func NewClient(consumerKey, consumerSecret string) (*Twitter, error) {
	oauth := OAuth{
		ConsumerKey:     consumerKey,
		ConsumerSecret:  consumerSecret,
		Version:         "1.0",
		SignatureMethod: "HMAC-SHA1",
	}

	if err := oauth.requestToken(); err != nil {
		return nil, err
	}

	return &Twitter{
		oauth: oauth,
	}, nil
}

// OAuthAuthentificateURL ...
func (t *Twitter) OAuthAuthentificateURL() string {
	return twitterOauthAuthenticateURL + "?oauth_token=" + t.oauth.Token
}

// AccessToken ...
func (t *Twitter) AccessToken(code string) error {
	v := url.Values{}
	v.Set("oauth_verifier", code)

	req, err := http.NewRequest("POST", twitterAccessTokenURL, strings.NewReader(normalizeParameters(v)))
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", contentType)
	req.Header.Add("User-Agent", userAgent)
	req.Header.Add("Authorization",
		oauthAuthorizationHeader(t.oauth, "POST", twitterAccessTokenURL, v),
	)

	client := &http.Client{Timeout: time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("response status=%d", resp.StatusCode)
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	m, err := url.ParseQuery(string(bodyBytes))
	if err != nil {
		return err
	}

	// set result
	t.oauth.Token = m.Get("oauth_token")
	t.oauth.TokenSecret = m.Get("oauth_token_secret")
	return nil
}

// Token ...
func (t *Twitter) Token(token, secret string) {
	t.oauth.Token = token
	t.oauth.TokenSecret = secret
}

func (oauth *OAuth) requestToken() error {
	v := url.Values{}
	v.Set("oauth_callback", "oob")

	req, err := http.NewRequest("POST", twitterRequestTokenURL, nil)
	if err != nil {
		return err
	}

	req.Header.Add("Content-Type", contentType)
	req.Header.Add("User-Agent", userAgent)
	req.Header.Add("Authorization",
		oauthAuthorizationHeader(*oauth, "POST", twitterRequestTokenURL, v))

	client := &http.Client{Timeout: time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("response status=%d", resp.StatusCode)
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	m, err := url.ParseQuery(string(bodyBytes))
	if err != nil {
		return err
	}

	// set result
	oauth.Token = m.Get("oauth_token")
	oauth.TokenSecret = m.Get("oauth_token_secret")
	oauth.CallbackConfirmed = m.Get("oauth_callback_confirmed")
	return nil
}

package twitter

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	twitterAPI  = "https://api.twitter.com/1.1/"
	twitterAuth = "https://api.twitter.com/oauth2/token"

	twitterOauthURL             = "https://api.twitter.com/oauth"
	twitterRequestTokenURL      = twitterOauthURL + "/request_token"
	twitterAccessTokenURL       = twitterOauthURL + "/access_token"
	twitterOauthAuthenticateURL = twitterOauthURL + "/authenticate"

	twitterStatusesUpdate = "https://api.twitter.com/1.1/statuses/update.json"

	contentType = "application/x-www-form-urlencoded;charset=UTF-8"
	userAgent   = "go-twitter v0.1"
)

// Twitter ...
type Twitter struct {
	oauth    Oauth
	Statuses *Statuses
}

// Token ...
type Token struct {
	Type        string `json:"token_type"`
	AccessToken string `json:"access_token"`
}

// Oauth ...
type Oauth struct {
	ConsumerKey       string
	ConsumerSecret    string
	Version           string
	SignatureMethod   string
	Token             string
	TokenSecret       string
	CallbackConfirmed string

	AOAToken Token
}

// New TwitterClient ...
func NewTwitterClient(consumerKey, consumerSecret string) (*Twitter, error) {
	oauth := Oauth{
		ConsumerKey:     consumerKey,
		ConsumerSecret:  consumerSecret,
		Version:         "1.0",
		SignatureMethod: "HMAC-SHA1",
	}

	if err := oauth.requestToken(); err != nil {
		return nil, err
	}

	fmt.Println(oauth)
	return &Twitter{
		oauth:    oauth,
		Statuses: newStatuses(oauth),
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

func (oauth *Oauth) requestToken() error {
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

// AuthAOA registers in twitter API and returns bearer key
func AuthAOA(consumer, secret string) (*Twitter, error) {
	credentials := strings.Join([]string{consumer, secret}, ":")
	encoded := base64.StdEncoding.EncodeToString([]byte(credentials))

	body := strings.NewReader("grant_type=client_credentials")

	req, err := http.NewRequest("POST", twitterAuth, body)
	req.Header.Add("Content-Type", contentType)
	req.Header.Add("Authorization", "Basic "+encoded)
	req.Header.Add("User-Agent", userAgent)

	client := &http.Client{Timeout: time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s is not available: code=%d", twitterAuth, resp.StatusCode)
	}
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var oauth Oauth
	if err = json.Unmarshal(bodyBytes, &oauth.AOAToken); err != nil {
		return nil, err
	}

	return &Twitter{
		Statuses: newStatuses(oauth),
	}, nil
}

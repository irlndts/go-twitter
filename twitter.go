package twitter

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	twitterAPI             = "https://api.twitter.com/1.1/"
	twitterAuth            = "https://api.twitter.com/oauth2/token"
	twitterRequestTokenURL = "https://api.twitter.com/oauth/request_token"
	twitterAccessTokenURL  = "https://api.twitter.com/oauth/access_token"

	twitterStatusesUpdate = "https://api.twitter.com/1.1/statuses/update.json"

	contentType = "application/x-www-form-urlencoded;charset=UTF-8"
	userAgent   = "go-twitter v0.1"
)

type Twitter struct {
	oauth    Oauth
	Statuses *Statuses
}

type Token struct {
	Type        string `json:"token_type"`
	AccessToken string `json:"access_token"`
}

type Oauth struct {
	ConsumerKey       string
	ConsumerSecret    string
	Version           string
	SignatureMethod   string
	Token             string
	TokenSecret       string
	CallbackConfirmed string
}

func NewTwitterClient(consumerKey, consumerSecret string) (*Twitter, error) {
	twitter := &Twitter{
		oauth: Oauth{
			ConsumerKey:     consumerKey,
			ConsumerSecret:  consumerSecret,
			Version:         "1.0",
			SignatureMethod: "HMAC-SHA1",
		},
	}

	if err := twitter.requestToken(); err != nil {
		return nil, err
	}

	return twitter, nil
}

// oauthAuthorizationHeader prepares authorization header
func (t *Twitter) oauthAuthorizationHeader(method, uri string, v url.Values) string {
	v.Set("oauth_nonce", t.nonce())
	v.Set("oauth_timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	v.Set("oauth_consumer_key", t.oauth.ConsumerKey)
	v.Set("oauth_signature_method", t.oauth.SignatureMethod)
	v.Set("oauth_version", t.oauth.Version)
	parameterString := v.Encode()

	signatureBaseString := strings.Join([]string{
		method,
		url.QueryEscape(uri),
		url.QueryEscape(parameterString),
	}, "&")

	signingKey := url.QueryEscape(t.oauth.ConsumerSecret) + "&"
	// authorization request doesn't have oauth_token_secret
	if t.oauth.TokenSecret != "" {
		signingKey = signingKey + url.QueryEscape(t.oauth.TokenSecret)
	}

	mac := hmac.New(sha1.New, []byte(signingKey))
	mac.Write([]byte(signatureBaseString))
	v.Set("oauth_signature", base64.URLEncoding.EncodeToString(mac.Sum(nil)))

	var oauths []string
	for k, _ := range v {
		// get only oauth_ params to set them into authorization string
		if strings.HasPrefix(k, "oauth_") {
			oauths = append(oauths, k+`="`+url.QueryEscape(v.Get(k))+`"`)
		}
	}
	return `OAuth ` + strings.Join(oauths, ", ")
}

func (t *Twitter) Update(status string) {

	v := url.Values{}
	authorization := t.oauthAuthorizationHeader("POST", twitterStatusesUpdate, v)

	body := strings.NewReader("status=" + status)

	req, err := http.NewRequest("POST", twitterStatusesUpdate, body)
	req.Header.Add("Authorization", authorization)
	req.Header.Add("Content-Type", contentType)
	req.Header.Add("User-Agent", userAgent)

	client := &http.Client{Timeout: time.Second}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	/*
		m, err := url.ParseQuery(string(bodyBytes))
		if err != nil {
			log.Fatal(err)
		}
	*/
	fmt.Println(string(bodyBytes))

}

func (t *Twitter) AccessToken(code string) {

	v := url.Values{}
	authorization := t.oauthAuthorizationHeader("POST", twitterAccessTokenURL, v)
	body := strings.NewReader("oauth_verifier=" + code)

	req, err := http.NewRequest("POST", twitterAccessTokenURL, body)
	req.Header.Add("Authorization", authorization)
	req.Header.Add("Content-Type", contentType)
	req.Header.Add("User-Agent", userAgent)

	client := &http.Client{Timeout: time.Second}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	/*
		m, err := url.ParseQuery(string(bodyBytes))
		if err != nil {
			log.Fatal(err)
		}
	*/
	fmt.Println(string(bodyBytes))

}

func (t *Twitter) requestToken() error {

	v := url.Values{}
	v.Set("oauth_callback", "oob")

	req, err := http.NewRequest("POST", twitterRequestTokenURL, nil)
	if err != nil {
		return err
	}

	req.Header.Add("Content-Type", contentType)
	req.Header.Add("User-Agent", userAgent)
	req.Header.Add("Authorization",
		t.oauthAuthorizationHeader("POST", twitterRequestTokenURL, v))

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
	t.oauth.CallbackConfirmed = m.Get("oauth_callback_confirmed")
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

	var token Token
	if err = json.Unmarshal(bodyBytes, &token); err != nil {
		return nil, err
	}

	return &Twitter{
		Statuses: newStatuses(token),
	}, nil
}

func (t *Twitter) nonce() string {
	token := make([]byte, 32)
	rand.Read(token)

	var nonce string

	encoded := base64.StdEncoding.EncodeToString(token)
	for _, e := range encoded {
		if unicode.IsLetter(e) {
			nonce += string(e)
		}
	}
	return nonce
}

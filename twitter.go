package twitter

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
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

func NewTwitterClient(consumerKey, consumerSecret string) *Twitter {
	twitter := &Twitter{
		oauth: Oauth{
			ConsumerKey:     consumerKey,
			ConsumerSecret:  consumerSecret,
			Version:         "1.0",
			SignatureMethod: "HMAC-SHA1",
		},
	}

	return twitter
}

func (t *Twitter) OauthAuthorizationHeader(method, uri string) string {
	oauth_timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	oauth_nonce := t.nonce()

	v := url.Values{}
	v.Set("oauth_nonce", oauth_nonce)
	v.Set("oauth_timestamp", oauth_timestamp)
	v.Set("oauth_consumer_key", t.oauth.ConsumerKey)
	v.Set("oauth_signature_method", t.oauth.SignatureMethod)
	v.Set("oauth_version", t.oauth.Version)
	v.Set("oauth_callback", "oob")
	parameterString := v.Encode()

	signatureBaseString := strings.Join([]string{
		method,
		url.QueryEscape(uri),
		url.QueryEscape(parameterString),
	}, "&")

	signingKey := url.QueryEscape(t.oauth.ConsumerSecret) + "&"

	mac := hmac.New(sha1.New, []byte(signingKey))
	mac.Write([]byte(signatureBaseString))

	oauth_signature := base64.URLEncoding.EncodeToString(mac.Sum(nil))

	authorization := `OAuth ` +
		`oauth_consumer_key="` + url.QueryEscape(t.oauth.ConsumerKey) + `", ` +
		`oauth_nonce="` + url.QueryEscape(oauth_nonce) + `", ` +
		`oauth_signature="` + url.QueryEscape(oauth_signature) + `", ` +
		`oauth_signature_method="` + url.QueryEscape(t.oauth.SignatureMethod) + `", ` +
		`oauth_timestamp="` + url.QueryEscape(oauth_timestamp) + `", ` +
		`oauth_version="` + url.QueryEscape(t.oauth.Version) + `"`

	return authorization
}

func (t *Twitter) Login() {

	authorization := t.OauthAuthorizationHeader("POST", twitterRequestTokenURL)
	body := strings.NewReader("oauth_callback=oob")

	// step 1
	req, err := http.NewRequest("POST", twitterRequestTokenURL, body)
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

	m, err := url.ParseQuery(string(bodyBytes))
	if err != nil {
		log.Fatal(err)
	}

	t.oauth.Token = m.Get("oauth_token")
	t.oauth.TokenSecret = m.Get("oauth_token_secret")
	t.oauth.CallbackConfirmed = m.Get("oauth_callback_confirmed")
	fmt.Println(t)

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
		return nil, fmt.Errorf("%s is not available: code=%s", twitterAuth, resp.StatusCode)
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

package twitter

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
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

func (t *Twitter) OauthAuthenticateString() string {
	return twitterOauthAuthenticateURL + "?oauth_token=" + t.oauth.Token
}

// oauthAuthorizationHeader prepares authorization header
func (t *Twitter) oauthAuthorizationHeader(method, uri string, v url.Values) string {
	v.Set("oauth_nonce", t.nonce())
	v.Set("oauth_timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	v.Set("oauth_consumer_key", t.oauth.ConsumerKey)
	v.Set("oauth_signature_method", t.oauth.SignatureMethod)
	v.Set("oauth_version", t.oauth.Version)
	if t.oauth.Token != "" {
		v.Set("oauth_token", t.oauth.Token)
	}

	signatureBaseString := strings.Join([]string{
		method,
		url.QueryEscape(uri),
		// TODO(irlndts): can't user v.Encode(), see https://github.com/golang/go/issues/4013
		url.QueryEscape(normalizeParameters(v)),
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
		if strings.HasPrefix(k, "oauth_") && k != "oauth_verifier" {
			oauths = append(oauths, k+`="`+url.QueryEscape(v.Get(k))+`"`)
		}
	}
	return `OAuth ` + strings.Join(oauths, ", ")
}

func (t *Twitter) AccessToken(code string) error {

	v := url.Values{}
	v.Set("oauth_verifier", code)

	req, err := http.NewRequest("POST", twitterAccessTokenURL, strings.NewReader(normalizeParameters(v)))
	req.Header.Add("Content-Type", contentType)
	req.Header.Add("User-Agent", userAgent)
	req.Header.Add("Authorization",
		t.oauthAuthorizationHeader("POST", twitterAccessTokenURL, v),
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

// PercentEncode percent encodes a string according to RFC 3986 2.1.
func PercentEncode(input string) string {
	var buf bytes.Buffer
	for _, b := range []byte(input) {
		// if in unreserved set
		if shouldEscape(b) {
			buf.Write([]byte(fmt.Sprintf("%%%02X", b)))
		} else {
			// do not escape, write byte as-is
			buf.WriteByte(b)
		}
	}
	return buf.String()
}

// RFC 3986 2.1.
func shouldEscape(c byte) bool {
	// RFC3986 2.3 unreserved characters
	if 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' {
		return false
	}
	switch c {
	case '-', '.', '_', '~':
		return false
	}
	// all other bytes must be escaped
	return true
}

func normalizeParameters(v url.Values) string {
	params := make([]string, 0, len(v))
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		params = append(params, fmt.Sprintf("%s=%s", PercentEncode(k), PercentEncode(v.Get(k))))
	}
	return strings.Join(params, "&")
}

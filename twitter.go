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
)

const (
	twitterAPI  = "https://api.twitter.com/1.1/"
	twitterAuth = "https://api.twitter.com/oauth2/token"

	contentType = "application/x-www-form-urlencoded;charset=UTF-8"
	userAgent   = "go-twitter v0.1"
)

type Twitter struct {
	Statuses *Statuses
}

type Token struct {
	Type        string `json:"token_type"`
	AccessToken string `json:"access_token"`
}

func Auth() {

	token := make([]byte, 32)
	rand.Read(token)

	oauth_nonce := base64.StdEncoding.EncodeToString(token)
	timestamp := time.Now().Unix()
	oauth_timestamp := strconv.FormatInt(timestamp, 10)
	oauth_signature_method := "HMAC-SHA1"
	oauth_version := "1.0"

	body := strings.NewReader("oauth_callback=oob")

	v := url.Values{}
	v.Set("oauth_nonce", oauth_nonce)
	v.Set("oauth_timestamp", oauth_timestamp)
	v.Set("oauth_consumer_key", oauth_consumer_key)
	v.Set("oauth_token", oauth_token)
	v.Set("oauth_signature_method", oauth_signature_method)
	v.Set("oauth_version", oauth_version)
	v.Set("oauth_callback", "oob")

	parameterString := v.Encode()
	method := "POST"
	uri := "https://api.twitter.com/oauth/request_token"

	signatureBaseString := strings.Join([]string{
		method,
		url.QueryEscape(uri),
		url.QueryEscape(parameterString),
	}, "&")

	signingKey := strings.Join([]string{
		url.QueryEscape(oauth_consumer_secret),
		url.QueryEscape(oauth_token_secret),
	}, "&")

	mac := hmac.New(sha1.New, []byte(signingKey))
	mac.Write([]byte(signatureBaseString))

	oauth_signature := base64.URLEncoding.EncodeToString(mac.Sum(nil))

	dst := `OAuth ` +
		`oauth_consumer_key="` + url.QueryEscape(oauth_consumer_key) + `", ` +
		`oauth_nonce="` + url.QueryEscape(oauth_nonce) + `", ` +
		`oauth_signature="` + url.QueryEscape(oauth_signature) + `", ` +
		`oauth_signature_method="` + url.QueryEscape(oauth_signature_method) + `", ` +
		`oauth_timestamp="` + url.QueryEscape(oauth_timestamp) + `", ` +
		`oauth_token="` + url.QueryEscape(oauth_token) + `", ` +
		`oauth_version=` + url.QueryEscape(oauth_version) + `"`

	// step 1
	req, err := http.NewRequest(method, uri, body)
	req.Header.Add("Authorization", dst)

	client := &http.Client{Timeout: time.Second}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	/*
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("%s is not available: code=%s", twitterAuth, resp.StatusCode)
		}
	*/
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(bodyBytes))

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

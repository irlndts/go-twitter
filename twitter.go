package twitter

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
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

// Auth registers in twitter API and returns bearer key
func Auth(consumer, secret string) (*Twitter, error) {
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

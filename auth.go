package twitter

import (
	"encoding/base64"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

// Auth registers in twitter API and returns bearer key
func Auth(consumer, secret string) (string, error) {
	credentials := strings.Join([]string{consumer, secret}, ":")
	encoded := base64.StdEncoding.EncodeToString([]byte(credentials))

	body := strings.NewReader("grant_type=client_credentials")

	req, err := http.NewRequest("POST", twitterAuth, body)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")
	req.Header.Add("Authorization", "Basic "+encoded)
	req.Header.Add("User-Agent", "go-twitter v0.1")

	client := &http.Client{Timeout: time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	/*
		if resp.Code != http.StatusOK{
			return "",
		}
	*/

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(bodyBytes), nil
}

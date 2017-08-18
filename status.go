package twitter

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

type Statuses struct {
	token Token
}

func newStatuses(token Token) *Statuses {
	return &Statuses{token: token}
}

func (s *Statuses) Update(status string) error {
	body := strings.NewReader("status=" + status)

	req, err := http.NewRequest("POST", twitterAPI+`statuses/update.json`, body)
	req.Header.Add("Content-Type", contentType)
	req.Header.Add("Authorization", "Bearer "+s.token.AccessToken)
	req.Header.Add("User-Agent", userAgent)

	client := &http.Client{Timeout: time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	/*
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("%s is not available: code=%s", twitterAuth, resp.StatusCode)
		}
	*/
	/*
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
	*/

	return nil
}

func (s *Statuses) UserTimeline(name string) error {
	body := "screen_name=" + name + "&count=1"

	fmt.Println(s.token.AccessToken)
	req, err := http.NewRequest("GET", twitterAPI+`statuses/user_timeline.json`+"?"+body, nil)
	req.Header.Add("Content-Type", contentType)
	req.Header.Add("Authorization", "Bearer "+s.token.AccessToken)
	req.Header.Add("User-Agent", userAgent)

	fmt.Println(req)
	client := &http.Client{Timeout: time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	fmt.Printf("%+v\n", resp)

	/*
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("%s is not available: code=%s", twitterAuth, resp.StatusCode)
		}
	*/
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	fmt.Println(string(bodyBytes))

	return nil
}

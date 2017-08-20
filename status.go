package twitter

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Statuses struct {
	token Token
}

func newStatuses(token Token) *Statuses {
	return &Statuses{token: token}
}

func (t *Twitter) Update(status string) error {
	v := url.Values{}
	v.Set("status", status)

	req, err := http.NewRequest("POST", twitterStatusesUpdate, strings.NewReader(v.Encode()))
	req.Header.Add("Content-Type", contentType)
	req.Header.Add("User-Agent", userAgent)
	req.Header.Add("Authorization",
		t.oauthAuthorizationHeader("POST", twitterStatusesUpdate, v),
	)

	client := &http.Client{Timeout: time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	/*
		        m, err := url.ParseQuery(string(bodyBytes))
				        if err != nil {
							            log.Fatal(err)
										        }
	*/
	fmt.Println(string(bodyBytes))
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

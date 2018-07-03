package main

import (
	"fmt"

	"github.com/irlndts/go-twitter"
)

func main() {
	consumer := ""
	secret := ""
	oauthToken := ""
	oauthTokenSecret := ""

	msg := "this is the second test message via github.com/irlndts/go-twitter"

	/*
		twitter, err := twitter.NewClient(consumer, secret)
		if err != nil {
			log.Printf("failed to create twitter client: %s", err)
			return
		}

		if err := twitter.Update(msg); err != nil {
			log.Printf("failed to update status: %s", err)
			return
		}
	*/
	twitter, err := twitter.NewClient(consumer, secret)
	if err != nil {
		fmt.Println(err)
		return
	}

	/*
		fmt.Printf("visit %s\nenter the code:", twitter.OAuthAuthentificateURL())
		reader := bufio.NewReader(os.Stdin)
		code, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println(err)
			return
		}

		if err = twitter.AccessToken(code); err != nil {
			fmt.Printf("access token err=%s", err)
			return
		}
	*/
	twitter.Token(oauthToken, oauthTokenSecret)

	if err = twitter.Update(msg); err != nil {
		fmt.Println(err)
	}
}

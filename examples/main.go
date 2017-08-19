package main

import (
	"fmt"

	"github.com/irlndts/go-twitter"
)

func main() {
	consumer := ""
	secret := ""
	twitter, err := twitter.NewTwitterClient(consumer, secret)
	if err != nil {
		panic(err)
	}
	fmt.Println(twitter)
	//twitter.Update("TEST")
	/*
		twitter, err := twitter.Auth(consumer, secret)
		if err != nil {
			panic(err)
		}

		if err = twitter.Statuses.UserTimeline("irlndts"); err != nil {
			panic(err)
		}
	*/
}

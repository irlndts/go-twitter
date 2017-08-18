package main

import "github.com/irlndts/go-twitter"

func main() {
	twitter.Auth()

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

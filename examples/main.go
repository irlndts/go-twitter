package main

import "github.com/irlndts/go-twitter"

func main() {
	consumer := ""
	secret := ""
	twitter := twitter.NewTwitterClient(consumer, secret)
	//twitter.Login()
	twitter.Update("TEST")
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

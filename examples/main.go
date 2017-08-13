package main

import (
	"fmt"
	"github.com/irlndts/go-twitter"
)

func main() {
	consumer := ""
	secret := ""
	bearer, err := twitter.Auth(consumer, secret)
	if err != nil {
		panic(err)
	}
	fmt.Println(bearer)
}

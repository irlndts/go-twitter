package main

import (
	"bufio"
	"fmt"
	"os"

	"github.com/irlndts/go-twitter"
)

func main() {
	consumer := ""
	secret := ""
	twitter, err := twitter.NewTwitterClient(consumer, secret)
	if err != nil {
		fmt.Println(err)
		return
	}

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

	if err = twitter.Update("Oi!"); err != nil {
		fmt.Println(err)
	}
}

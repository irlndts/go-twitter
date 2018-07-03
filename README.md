# go-twitter
Simple Twitter API client to send tweets.

## Installation
```
go get github.com/irlndts/go-twitter
```

## Usage

First of all your application requires `Consumer Key` and `Consumer Secret`. 
Create your app here https://apps.twitter.com
Switch to `Keys and Access Tokens` and find `Consumer Key` and `Consumer Secret` there.

If you use the app by yourself only use `Access Token` and `Access Token Secret` from the same page.

```go
func main(){
	consumer := "consumer key"
	secret := "consumer secret"
	accessToken := "access token"
	accessTokenSecret := "access token secret"

	twitter, err := twitter.NewClient(consumer, secret)
	if err != nil {
		panic(err)
	}

	twitter.Token(oauthToken, oauthTokenSecret)
	if err = twitter.Update("Hello, twitter!"); err != nil {
		panic(err)
    	}
}
```

If you want to allow other users use your app, you should ask them to authenticate
```go
func main(){
	consumer := "consumer key"
	secret := "consumer secret"

	twitter, err := twitter.NewClient(consumer, secret)
	if err != nil {
		panic(err)
    	}
	
	// ask your client to visit the link, authorize app and receive authentication code
	fmt.Printf("visit %s\n", twitter.OAuthAuthentificateURL())
	
	// use the code client has got
	code := "12345"
	if err = twitter.AccessToken("1345"); err != nil {
		panic(err)
	}

	if err = twitter.Update("Hello, twitter!"); err != nil {
		panic(err)
   	}
}
```

# go-twitter
Simple Twitter API client to send tweets.

## Installation
```
go get github.com/irlndts/go-twitter
```

## Usage

First of all your application requires Consumer Key and Consumer Secret. 
Create your app here https://apps.twitter.com
Switch to `Keys and Access Tokens` and find Consumer Key and Consumer Secret there.

If you use the app by yourself only use Access Token and Access Token Secret from the same page.

```go
func main(){
	consumer := "consumer key"
	secret := "consumer secret"
	accessToken := "access token"
	accessTokenSecret := "access token secret"

	twitter, _ := twitter.NewClient(consumer, secret)
	twitter.Token(accessToken, accessTokenSecret)
	twitter.Update("Hello, twitter!")
}
```

If you want to allow other users use your app, you should ask them to authenticate
```go
func main(){
	consumer := "consumer key"
	secret := "consumer secret"

	twitter, _ := twitter.NewClient(consumer, secret)
	
	// ask your client to visit the link, authorize app and receive authentication code
	fmt.Printf("visit %s\n", twitter.OAuthAuthentificateURL())
	// wait for the code
	code := "12345"
	twitter.AccessToken(code)
	twitter.Update("Hello, twitter!")
}
```

package twitter

const (
	twitterAPI  = "https://api.twitter.com/1.1/"
	twitterAuth = "https://api.twitter.com/oauth2/token"
)

// Client ...
type Client struct{}

// NewClient creates new twitter client
func NewClient() *Client {
	return &Client{}
}

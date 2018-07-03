package twitter

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

func nonce() string {
	token := make([]byte, 32)
	rand.Read(token)

	var nonce string
	encoded := base64.StdEncoding.EncodeToString(token)
	for _, e := range encoded {
		if unicode.IsLetter(e) {
			nonce += string(e)
		}
	}
	return nonce
}

// percentEncode percent encodes a string according to RFC 3986 2.1.
func percentEncode(input string) string {
	var buf bytes.Buffer
	for _, b := range []byte(input) {
		// if in unreserved set
		if shouldEscape(b) {
			buf.Write([]byte(fmt.Sprintf("%%%02X", b)))
		} else {
			// do not escape, write byte as-is
			buf.WriteByte(b)
		}
	}
	return buf.String()
}

// RFC 3986 2.1.
func shouldEscape(c byte) bool {
	// RFC3986 2.3 unreserved characters
	if 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' {
		return false
	}
	switch c {
	case '-', '.', '_', '~':
		return false
	}
	// all other bytes must be escaped
	return true
}

func normalizeParameters(v url.Values) string {
	params := make([]string, 0, len(v))
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		params = append(params, fmt.Sprintf("%s=%s", percentEncode(k), percentEncode(v.Get(k))))
	}
	return strings.Join(params, "&")
}

// oauthAuthorizationHeader prepares authorization header
func oauthAuthorizationHeader(oauth OAuth, method, uri string, v url.Values) string {
	v.Set("oauth_nonce", nonce())
	v.Set("oauth_timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	v.Set("oauth_consumer_key", oauth.ConsumerKey)
	v.Set("oauth_signature_method", oauth.SignatureMethod)
	v.Set("oauth_version", oauth.Version)
	if oauth.Token != "" {
		v.Set("oauth_token", oauth.Token)
	}

	signatureBaseString := strings.Join([]string{
		method,
		url.QueryEscape(uri),
		// TODO(irlndts): can't user v.Encode(), see https://github.com/golang/go/issues/4013
		url.QueryEscape(normalizeParameters(v)),
	}, "&")

	signingKey := url.QueryEscape(oauth.ConsumerSecret) + "&"
	// authorization request doesn't have oauth_token_secret
	if oauth.TokenSecret != "" {
		signingKey = signingKey + url.QueryEscape(oauth.TokenSecret)
	}

	mac := hmac.New(sha1.New, []byte(signingKey))
	mac.Write([]byte(signatureBaseString))
	v.Set("oauth_signature", base64.URLEncoding.EncodeToString(mac.Sum(nil)))

	var oauths []string
	for k := range v {
		// get only oauth_ params to set them into authorization string
		if strings.HasPrefix(k, "oauth_") && k != "oauth_verifier" {
			oauths = append(oauths, k+`="`+url.QueryEscape(v.Get(k))+`"`)
		}
	}
	return `OAuth ` + strings.Join(oauths, ", ")
}

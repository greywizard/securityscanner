package securityscanner

import (
	"errors"
	"net/url"
	"time"

	"github.com/r--w/gorequest"
	"github.com/spf13/viper"
)

var maxRedirects int = 5
var maxBodyLength int64 = 5000000

// DefualtTimeout for GET/POST calls
var DefaultTimeout time.Duration = 12 * time.Second

func checkRedirect(req gorequest.Request, via []gorequest.Request) error {
	if len(via) > maxRedirects {
		return errors.New("MaxRedirects reached")
	}
	//By default Golang will not redirect request headers
	// https://code.google.com/p/go/issues/detail?id=4800&q=request%20header
	for key, val := range via[0].Header {
		req.Header[key] = val
	}
	return nil
}

// HtttGet do GET call
func HttpGet(uri string, timeout time.Duration) (gorequest.Response, string, error) {
	response, body, errs := gorequest.New().
		Get(uri).
		Set("User-Agent", viper.GetString("bot_name")).
		Timeout(timeout).
		SetMaxResponseBodyLength(maxBodyLength).
		RedirectPolicy(checkRedirect).
		End()

	if len(errs) > 0 {
		return response, body, errs[0]
	}
	return response, body, nil
}

// HtttGet do POST call
func HttpPost(uri string, timeout time.Duration, params url.Values) (gorequest.Response, string, error) {
	response, body, errs := gorequest.New().
		Post(uri).
		Set("User-Agent", viper.GetString("bot_name")).
		Send(params.Encode()).
		Timeout(timeout).
		SetMaxResponseBodyLength(maxBodyLength).
		RedirectPolicy(checkRedirect).
		End()

	if len(errs) > 0 {
		return response, body, errs[0]
	}
	return response, body, nil
}

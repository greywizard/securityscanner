package headers

import (
	"strings"
	"time"

	"github.com/greywizard/securityscanner/securityscanner"
	"github.com/greywizard/securityscanner/securityscanner/logger"
	"github.com/greywizard/securityscanner/securityscanner/translate"
)

type HeadersPlugin struct {
	securityscanner.Plugin
}

func (s *HeadersPlugin) Code() string {
	return "Headers"
}

func (s *HeadersPlugin) Name() string {
	return translate.Translate("HTTP Headers")
}

func (s *HeadersPlugin) Info() map[string]interface{} {
	return map[string]interface{}{
		"X-Xss-Protection":          translate.Translate(`"X-Xss-Protection" header sets the configuration for the cross-site scripting filter built into most browsers. Recommended value "X-XSS-Protection: 1; mode=block".`),
		"X-Frame-Options":           translate.Translate(`"X-Frame-Options" header tells the browser whether you want to allow your site to be framed or not. By preventing a browser from framing your site you can defend against attacks like clickjacking.`),
		"Strict-Transport-Security": translate.Translate(`"Strict-Transport-Security" header Excellent feature to support on your site and strengthens your implementation of TLS by getting the User Agent to enforce the use of HTTPS. Recommended value "strict-transport-security: max-age=31536000; includeSubdomains`),
		"Content-Security-Policy":   translate.Translate(`"Content-Security-Policy" header Effective measure to protect your site from XSS attacks. By whitelisting sources of approved content, you can prevent the browser from loading malicious assets`),
		"X-Content-Type-Options":    translate.Translate(`"X-Content-Type-Options" header Stops a browser from trying to MIME-sniff the content type and forces it to stick with the declared content-type. The only valid value for this header is "X-Content-Type-Options: nosniff`),
		"X-Powered-By":              translate.Translate(`"X-Powered-By" header Can usually be seen with values like "PHP/5.5.9-1ubuntu4.5" or "ASP.NET". Trying to minimise the amount of information you give out about your server is a good idea. This header should be removed or the value changed.`),
		"X-AspNet-Version":          translate.Translate(`"X-AspNet-Version" header Details specific information about your ASP.NET version and should be remove.`),
		"Server":                    translate.Translate(`"Server" header Designed to give information about the particular Web Server application being run on the server. Trying to minimise the amount of information you give out about your server is a good idea. This header should be removed or the value changed.`),
	}
}

func (s *HeadersPlugin) Scan() (map[string]interface{}, error) {
	s.Validate()

	defer func(start time.Time) {
		logger.LoggerDebug.Debugf("[TIME] %s/%s/%s: %s", s.Code(), s.Domain, translate.GetLang(), time.Since(start))
	}(time.Now())

	logger.LoggerDebug.Debugf("[SCANNER] %s: %s", s.Code(), s.Domain)

	value := map[string]interface{}{}

	response, _, err := securityscanner.HttpGet(s.Protocol+"://"+s.Domain, securityscanner.DefaultTimeout)

	if err != nil {
		return value, err
	}

	headersPositive := map[string]interface{}{
		"X-Xss-Protection":          securityscanner.YELLOW,
		"X-Frame-Options":           securityscanner.YELLOW,
		"Strict-Transport-Security": securityscanner.YELLOW,
		"Content-Security-Policy":   securityscanner.YELLOW,
		"X-Content-Type-Options":    securityscanner.YELLOW,
	}

	for k, v := range headersPositive {
		value[k] = v
		if _, ok := response.Header[k]; ok {
			value[k] = securityscanner.GREEN
		}
	}

	headersNegative := map[string]interface{}{
		"X-Powered-By":     securityscanner.YELLOW,
		"X-AspNet-Version": securityscanner.YELLOW,
	}

	value["Server"] = securityscanner.GREEN
	if _, ok := response.Header["Server"]; ok {
		server := strings.ToLower(strings.Join(response.Header["Server"], ","))
		if strings.Contains(server, "nginx") || strings.Contains(server, "apache") {
			value["Server"] = securityscanner.YELLOW
		}
	}

	for k, v := range headersNegative {
		value[k] = securityscanner.GREEN
		if _, ok := response.Header[k]; ok {
			value[k] = v
		}
	}

	return value, nil
}

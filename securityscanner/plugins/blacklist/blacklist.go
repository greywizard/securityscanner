package blacklist

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"strings"
	"sync"

	simplejson "github.com/bitly/go-simplejson"
	"github.com/greywizard/securityscanner/securityscanner"
	"github.com/greywizard/securityscanner/securityscanner/logger"
	"github.com/greywizard/securityscanner/securityscanner/translate"
	"github.com/spf13/viper"
)

var (
	googleApiKey     string
	virustotalApiKey string
)

type BlacklistPlugin struct {
	securityscanner.Plugin
}

func (s *BlacklistPlugin) Code() string {
	return "Blacklist"
}

func (s *BlacklistPlugin) Name() string {
	return translate.Translate("Blacklists")
}

func (s *BlacklistPlugin) Info() map[string]interface{} {
	return map[string]interface{}{
		"safebrowsing": translate.Translate(`"Safe Browsing" is a Google service that enables applications to check URLs against constantly updated lists of suspected phishing, malware, and unwanted software pages.`),
		"bitdefender":  translate.Translate(`"Bitdefender" URL Status Service detects malicious, phishing, and fraudulent websites in real-time before it can infect your devices by checking URLs or IP addresses to determine if they are harmful`),
		"eset":         translate.Translate(`"ESET Online Scanner" is a free program for Microsoft Windows devices to run a one-time scan for malicious and potentially unwanted items.`),
		"kaspersky":    translate.Translate(`"Kaspersky" URL Status Service detects malicious, phishing, and fraudulent websites in real-time before it can infect your devices by checking URLs or IP addresses to determine if they are harmful`),
	}
}

func initConfig() error {
	var err error
	googleApiKey = viper.GetString("google_api_key")
	virustotalApiKey = viper.GetString("virustotal_api_key")

	if googleApiKey == "" {
		err = errors.New("google_api_key Not provided in configuration")
		logger.LoggerError.Error(err)
	}

	if virustotalApiKey == "" {
		err = errors.New("virustotal_api_key Not provided in configuration")
		logger.LoggerError.Error(err)
	}

	return err
}

func (s *BlacklistPlugin) Scan() (map[string]interface{}, error) {
	s.Validate()

	defer func(start time.Time) {
		logger.LoggerDebug.Debugf("[TIME] %s/%s/%s: %s", s.Code(), s.Domain, time.Since(start))
	}(time.Now())

	err := initConfig()
	if err != nil {
		if err != nil {
			return map[string]interface{}{}, err
		}
	}

	logger.LoggerDebug.Debugf("[SCANNER] %s: %s", s.Code(), s.Domain)

	value := map[string]interface{}{
		"bitdefender":  securityscanner.GREEN,
		"eset":         securityscanner.GREEN,
		"kaspersky":    securityscanner.GREEN,
		"safebrowsing": securityscanner.GREEN,
	}

	if response, errBL := isBlacklisted(s.Domain); errBL != nil {
		logger.LoggerError.Error(logger.Trace(errBL))
	} else if response {
		value["safebrowsing"] = securityscanner.RED
	}

	params := url.Values{}
	params.Set("url", "http://"+s.Domain)
	params.Set("apikey", virustotalApiKey)

	response, body, err := securityscanner.HttpPost("https://www.virustotal.com/vtapi/v2/url/scan", securityscanner.DefaultTimeout, params)

	if err != nil {
		return value, err
	}

	ticker := time.NewTicker(1 * time.Second)
	count := 0
	wg := new(sync.WaitGroup)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for t := range ticker.C {
			count++

			logger.LoggerDebug.Debugf("[VIRUSTOTAL] CHECK RESULTS AT: %s", t)
			params := url.Values{}
			params.Set("resource", "http://"+s.Domain)
			params.Set("apikey", virustotalApiKey)
			response, body, err = securityscanner.HttpPost("https://www.virustotal.com/vtapi/v2/url/report", securityscanner.DefaultTimeout, params)

			if count > 7 || err != nil || response.StatusCode != http.StatusOK {
				ticker.Stop()
				return
			}

			virusTotalBody, err := simplejson.NewJson([]byte(body))
			if err != nil {
				logger.LoggerError.Error(logger.Trace(err))
				ticker.Stop()
			}

			responseCode, err := virusTotalBody.Get("response_code").Float64()
			if err != nil {
				logger.LoggerError.Error(logger.Trace(err))
				ticker.Stop()
			}

			if responseCode > 0 {
				scans, err := virusTotalBody.Get("scans").Map()
				if err != nil {
					logger.LoggerError.Error(logger.Trace(err))
					ticker.Stop()
				}
				for _, v := range []string{"ESET", "BitDefender", "Kaspersky"} {
					if scans[v].(map[string]interface{})["detected"].(bool) {
						value[strings.ToLower(v)] = securityscanner.RED
					}
				}

				ticker.Stop()
				return
			}
		}
	}()
	wg.Wait()

	return value, nil
}

func isBlacklisted(domain string) (bool, error) {
	response, _, err := securityscanner.HttpGet(fmt.Sprintf("https://sb-ssl.google.com/safebrowsing/api/lookup?key=%s&url=%s&client=gw&appver=1.7&pver=3.1", googleApiKey, url.QueryEscape(domain)), 15*time.Second)

	if err != nil {
		return false, err
	}

	if response.StatusCode != http.StatusNoContent {
		return true, nil
	}

	return false, nil
}

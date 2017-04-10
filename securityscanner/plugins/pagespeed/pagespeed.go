package pagespeed

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/greywizard/securityscanner/securityscanner"
	"github.com/greywizard/securityscanner/securityscanner/logger"
	"github.com/greywizard/securityscanner/securityscanner/translate"
	"github.com/spf13/viper"
)

var pagespeedApiKey string

type PagespeedPlugin struct {
	securityscanner.Plugin
}

func (s *PagespeedPlugin) Code() string {
	return s.Name()
}

func (s *PagespeedPlugin) Name() string {
	return "Pagespeed"
}

func (s *PagespeedPlugin) Info() map[string]interface{} {
	return map[string]interface{}{}
}

func initConfig() error {
	var err error
	pagespeedApiKey = viper.GetString("pagespeed_api_key")

	if pagespeedApiKey == "" {
		err = errors.New("google_api_key Not provided in configuration")
		logger.LoggerError.Error(err)
	}

	return err
}

func (s *PagespeedPlugin) Scan() (map[string]interface{}, error) {
	s.Validate()

	defer func(start time.Time) {
		logger.LoggerDebug.Debugf("[TIME] %s/%s/%s: %s", s.Code(), s.Domain, translate.GetLang(), time.Since(start))
	}(time.Now())

	value := map[string]interface{}{}
	err := initConfig()
	if err != nil {
		if err != nil {
			return value, err
		}
	}

	//https://developers.google.com/speed/docs/insights/v2/first-app#example_commandline
	//https://developers.google.com/speed/docs/insights/v2/first-app#example_javascript
	logger.LoggerDebug.Debugf("[SCANNER] %s: %s", s.Code(), s.Domain)

	response, body, err := securityscanner.HttpGet("https://www.googleapis.com/pagespeedonline/v2/runPagespeed?url="+s.Protocol+"://"+s.Domain+"&strategy=desktop&screenshot=true&key="+pagespeedApiKey+"&locale="+string(translate.GetLang()), 20*time.Second)

	if err != nil {
		return value, err
	}

	if response.StatusCode != 200 {
		return value, errors.New(fmt.Sprintf("invalid response code: %d body: %s", response.StatusCode, body))
	}

	if err := json.Unmarshal([]byte(body), &value); err != nil {
		return value, err
	}

	return value, nil
}

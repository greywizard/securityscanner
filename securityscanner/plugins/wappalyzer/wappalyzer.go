package wappalyzer

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/greywizard/securityscanner/securityscanner"
	"github.com/greywizard/securityscanner/securityscanner/logger"
	"github.com/greywizard/securityscanner/securityscanner/translate"
	"github.com/spf13/viper"
)

var jsonRe *regexp.Regexp = regexp.MustCompile(`({.*})`)

type WappalyzerPlugin struct {
	securityscanner.Plugin
}

func (s *WappalyzerPlugin) Code() string {
	return s.Name()
}

func (s *WappalyzerPlugin) Name() string {
	return "Wappalyzer"
}

func (s *WappalyzerPlugin) Info() map[string]interface{} {
	categories := map[string]string{
		"cms":                   translate.Translate("CMS"),
		"message-boards":        translate.Translate("Message board"),
		"database-managers":     translate.Translate("Database manager"),
		"documentation-tools":   translate.Translate("Documentation tool"),
		"widgets":               translate.Translate("Widget"),
		"ecommerce":             translate.Translate("E-commerce"),
		"photo-galleries":       translate.Translate("Photo gallery"),
		"wikis":                 translate.Translate("Wiki"),
		"hosting-panels":        translate.Translate("Hosting panel"),
		"analytics":             translate.Translate("Analytics"),
		"blogs":                 translate.Translate("Blog"),
		"javascript-frameworks": translate.Translate("Javascript framework"),
		"issue-trackers":        translate.Translate("Issue tracker"),
		"video-players":         translate.Translate("Video player"),
		"comment-systems":       translate.Translate("Comment system"),
		"captchas":              translate.Translate("Captcha"),
		"font-scripts":          translate.Translate("Font script"),
		"web-frameworks":        translate.Translate("Web framework"),
		"miscellaneous":         translate.Translate("Miscellaneous"),
		"editors":               translate.Translate("Editor"),
		"lms":                   translate.Translate("LMS"),
		"web-servers":           translate.Translate("Web server"),
		"cache-tools":           translate.Translate("Cache tool"),
		"rich-text-editors":     translate.Translate("Rich text editor"),
		"javascript-graphics":   translate.Translate("Javascript graphic"),
		"mobile-frameworks":     translate.Translate("Mobile framework"),
		"programming-languages": translate.Translate("Programming language"),
		"operating-systems":     translate.Translate("Operating system"),
		"search-engines":        translate.Translate("Search engine"),
		"web-mail":              translate.Translate("Web-mail"),
		"cdn":                   translate.Translate("CDN"),
		"marketing-automation":        translate.Translate("Marketing automation"),
		"web-server-extensions":       translate.Translate("Web server extension"),
		"databases":                   translate.Translate("Database"),
		"maps":                        translate.Translate("Maps"),
		"advertising-networks":        translate.Translate("Advertising network"),
		"network-devices":             translate.Translate("Network device"),
		"media-servers":               translate.Translate("Media server"),
		"webcams":                     translate.Translate("Webcam"),
		"printers":                    translate.Translate("Printer"),
		"payment-processors":          translate.Translate("Payment processor"),
		"tag-managers":                translate.Translate("Tag manager"),
		"paywalls":                    translate.Translate("Paywall"),
		"build-ci-systems":            translate.Translate("Build CI system"),
		"control-systems":             translate.Translate("Control systems"),
		"remote-access":               translate.Translate("Remote-access"),
		"dev-tools":                   translate.Translate("Dev tool"),
		"network-storage":             translate.Translate("Network storage"),
		"feed-readers":                translate.Translate("Feed reader"),
		"document-management-systems": translate.Translate("Document management systems"),
		"landing-page-builders":       translate.Translate("Landing page builder"),
	}
	return map[string]interface{}{
		"Categories": categories,
	}
}

func (s *WappalyzerPlugin) Scan() (map[string]interface{}, error) {
	defer func(start time.Time) {
		logger.LoggerDebug.Debugf("[TIME] %s/%s/%s: %s", s.Code(), s.Domain, translate.GetLang(), time.Since(start))
	}(time.Now())

	logger.LoggerDebug.Debugf("[SCANNER] %s: %s", s.Code(), s.Domain)

	value := map[string]interface{}{}

	timeout := 25 * time.Second
	envW := os.Environ()
	isLocal := viper.GetBool("is_local")
	if isLocal {
		logger.LoggerDebug.Debug("[SCANNER] RUNNING DOCKER-MACHINE")
		cmdDM := exec.Command("docker-machine", "env")

		var outDM bytes.Buffer
		cmdDM.Stdout = &outDM
		_ = cmdDM.Run()

		for _, v := range strings.Split(outDM.String(), "\n") {
			if strings.Contains(v, "export") {
				envW = append(envW, strings.Replace(v[7:], `"`, "", -1))
			}
		}
	}

	logger.LoggerDebug.Debug("[SCANNER] RUNNING DOCKER")
	var outW bytes.Buffer
	cmdW := exec.Command("docker", "run", "--rm", "wappalyzer/grey_wizard", s.Protocol+"://"+s.Domain)
	cmdW.Env = envW
	cmdW.Stdout = &outW
	cmdW.Stderr = &outW
	if err := cmdW.Start(); err != nil {
		return value, err
	}

	timer := time.AfterFunc(timeout, func() {
		logger.LoggerError.Error("wappalyzer timeout")
		cmdW.Process.Kill()
	})
	defer timer.Stop()

	if err := cmdW.Wait(); err != nil {
		logger.LoggerError.Error("wappalyzer wait error output: ", outW.String())
		return value, err
	}

	valueJSON := outW.String()
	valueJSON = jsonRe.FindString(valueJSON)
	if valueJSON == "" {
		return value, errors.New("invalid json from wappalyzer: " + outW.String())
	}

	logger.LoggerDebug.Debug("[SCANNER] PHANTOMJS ", strings.Split(outW.String(), "\n"))
	if err := json.Unmarshal([]byte(valueJSON), &value); err != nil {
		return value, err
	} else {
		return value, err
	}
}

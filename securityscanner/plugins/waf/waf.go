package waf

import (
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/greywizard/securityscanner/securityscanner"
	"github.com/greywizard/securityscanner/securityscanner/logger"
	"github.com/greywizard/securityscanner/securityscanner/translate"
	"github.com/metakeule/fmtdate"
)

type WafPlugin struct {
	securityscanner.Plugin
}

func (s *WafPlugin) Code() string {
	return "Waf"
}

func (s *WafPlugin) Name() string {
	return "Web Application Firewall (WAF)"
}

func (s *WafPlugin) Info() map[string]interface{} {
	return map[string]interface{}{
		"provider":  translate.Translate(`A web application firewall (WAF) is an appliance, server plugin, or filter that applies a set of rules to an HTTP conversation. Generally, these rules cover common attacks such as cross-site scripting (XSS) and SQL injection.`),
		"xss":       translate.Translate(`Cross-Site Scripting (XSS) attacks are a type of injection, in which malicious scripts are injected into otherwise benign and trusted web sites.`),
		"sqli":      translate.Translate(`A SQL injection attack consists of insertion or "injection" of a SQL query via the input data from the client to the application. A successful SQL injection exploit can read sensitive data from the database, modify database data (Insert/Update/Delete), execute administration operations on the database.`),
		"traversal": translate.Translate(`A path traversal attack (also known as directory traversal) aims to access files and directories that are stored outside the web root folder.`),
		"cmd":       translate.Translate(`Command injection is an attack in which the goal is execution of arbitrary commands on the host operating system via a vulnerable application.`),
		"code":      translate.Translate(`Code Injection is the general term for attack types which consist of injecting code that is then interpreted/executed by the application. This type of attack exploits poor handling of untrusted data.`),
	}
}

func (s *WafPlugin) Scan() (map[string]interface{}, error) {
	s.Validate()

	defer func(start time.Time) {
		logger.LoggerDebug.Debugf("[TIME] %s/%s/%s: %s", s.Code(), s.Domain, translate.GetLang(), time.Since(start))
	}(time.Now())

	logger.LoggerDebug.Debugf("[SCANNER] %s: %s", s.Code(), s.Domain)

	value := map[string]interface{}{}

	response, _, err := securityscanner.HttpGet(s.Protocol+"://"+s.Domain+"/invalid_"+fmtdate.Format("YYYY_MM_DD_hh_mm_ss", time.Now())+"_hello", securityscanner.DefaultTimeout)

	if err != nil {
		return value, err
	}

	clearStatus := response.StatusCode

	value["provider"] = securityscanner.RED

	servers := []string{"cloudflare", "greywizard", "akamaighost"}
	for _, s := range servers {
		if strings.Contains(strings.ToLower(strings.Join(response.Header["Server"], ",")), s) {
			value["provider"] = securityscanner.GREEN
		}
	}

	cdns := []string{"incapsula"}
	for _, s := range cdns {
		if strings.Contains(strings.ToLower(strings.Join(response.Header["X-Cdn"], ",")), s) {
			value["provider"] = securityscanner.GREEN
		}
	}

	if _, ok := response.Header["X-Akamai-Transformed"]; ok {
		value["provider"] = securityscanner.GREEN
	}

	urls := map[string]string{
		"xss":       "?x=<script>alert(1)</script>",
		"traversal": "?x=../../../../etc/passwd",
		"sqli":      "?x=INSERT%20INTO%20users20VALUES(1,%20'ddd')",
		"cmd":       "?x=cmd.exe",
		"code":      "?x=%20system(%27id%27)",
	}

	wg := new(sync.WaitGroup)
	var mutex = new(sync.Mutex)

	for k, v := range urls {
		wg.Add(1)
		go func(key, url string) {
			defer wg.Done()
			logger.LoggerDebug.Debug("[SCANNER] WAF CHECK: ", key, url)
			time.Sleep(time.Duration(rand.Int31n(2000)) * time.Millisecond)

			t1 := time.Now()
			response, _, err := securityscanner.HttpGet(s.Protocol+"://"+s.Domain+"/"+url, securityscanner.DefaultTimeout)
			if err != nil {
				logger.LoggerError.Error(logger.Trace(err), " time: ", time.Since(t1))
				mutex.Lock()
				value[key] = securityscanner.YELLOW
				mutex.Unlock()
				return
			}

			mutex.Lock()
			value[key] = securityscanner.RED
			mutex.Unlock()

			//CloudFlare http.StatusServiceUnavailable gives that for JS redirects
			validStatuses := map[int]bool{
				http.StatusForbidden:          true,
				http.StatusTooManyRequests:    true,
				http.StatusServiceUnavailable: true,
				http.StatusNotAcceptable:      true,
			}

			if response.StatusCode == http.StatusForbidden && strings.Contains(strings.Join(response.Header["Server"], ","), "AkamaiGHost") {
				value["provider"] = securityscanner.GREEN
			}

			if response.StatusCode != http.StatusOK && (response.StatusCode != clearStatus || validStatuses[response.StatusCode]) {
				mutex.Lock()
				value[key] = securityscanner.GREEN
				mutex.Unlock()
			}
		}(k, v)
	}
	wg.Wait()

	return value, nil
}

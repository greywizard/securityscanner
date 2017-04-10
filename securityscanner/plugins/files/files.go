package files

import (
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/greywizard/securityscanner/securityscanner"
	"github.com/greywizard/securityscanner/securityscanner/logger"
	"github.com/greywizard/securityscanner/securityscanner/translate"
)

var htmlRe = regexp.MustCompile(`<html|html>|<body|body>`)

type FilesPlugin struct {
	securityscanner.Plugin
}

func (s *FilesPlugin) Code() string {
	return "Files"
}

func (s *FilesPlugin) Name() string {
	return translate.Translate("Sensitive files")
}

func (s *FilesPlugin) Info() map[string]interface{} {
	return map[string]interface{}{
		"git":      translate.Translate(`Git is a version control system that is widely used for software development and other version control tasks. Directory .git contains sensitive data and can not be public.`),
		"svn":      translate.Translate(`SVN is a version control system that is widely used for software development and other version control tasks. Directory .svn contains sensitive data and can not be public.`),
		"htaccess": translate.Translate(`A .htaccess (hypertext access) file is a directory-level configuration file supported by several web servers, used for configuration of site-access issues this file can not be public.`),
	}
}

func (s *FilesPlugin) Scan() (map[string]interface{}, error) {
	s.Validate()

	defer func(start time.Time) {
		logger.LoggerDebug.Debugf("[TIME] %s/%s/%s: %s", s.Code(), s.Domain, translate.GetLang(), time.Since(start))
	}(time.Now())

	logger.LoggerDebug.Debugf("[SCANNER] %s: %s", s.Code(), s.Domain)

	value := map[string]interface{}{
		"git":      securityscanner.GREEN,
		"svn":      securityscanner.GREEN,
		"htaccess": securityscanner.GREEN,
	}

	urls := map[string]string{
		"git":      ".git/config",
		"svn":      ".svn/entries",
		"htaccess": ".htaccess",
	}

	wg := new(sync.WaitGroup)
	var mutex = new(sync.Mutex)
	for k, v := range urls {
		wg.Add(1)
		go func(key, url string) {
			defer wg.Done()
			logger.LoggerDebug.Debug("[SCANNER] FILE CHECK: ", key, url)
			response, body, err := securityscanner.HttpGet(s.Protocol+"://"+s.Domain+"/"+url, securityscanner.DefaultTimeout)

			if err != nil {
				logger.LoggerError.Error(logger.Trace(err))
				mutex.Lock()
				value[key] = securityscanner.YELLOW
				mutex.Unlock()
				return
			}
			if response.StatusCode == http.StatusOK && body != "" && htmlRe.FindString(body) == "" && !strings.Contains(body, "403 Forbidden") {
				logger.LoggerDebug.Debugf("[SCANNER] FILE CHECK KEY: %s URL: %s CODE: %d  BODY: %s", key, url, response.StatusCode, body)
				mutex.Lock()
				value[key] = securityscanner.RED
				mutex.Unlock()
			}
		}(k, v)
	}
	wg.Wait()

	return value, nil
}

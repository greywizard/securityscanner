package main

import (
	"github.com/davecgh/go-spew/spew"
	"github.com/greywizard/securityscanner/securityscanner"
	"github.com/greywizard/securityscanner/securityscanner/logger"
	_ "github.com/greywizard/securityscanner/securityscanner/plugins"
	"github.com/greywizard/securityscanner/securityscanner/translate"
)

func main() {
	if err := translate.SetLang("en"); err != nil {
		logger.LoggerError.Warn(err)
	}

	plugin, err := securityscanner.GetPlugin("IP")
	//plugin, err := securityscanner.GetPlugin("Blacklist")
	//plugin, err := securityscanner.GetPlugin("Files")
	//plugin, err := securityscanner.GetPlugin("Headers")
	//plugin, err := securityscanner.GetPlugin("Https")
	//plugin, err := securityscanner.GetPlugin("Pagespeed")
	//plugin, err := securityscanner.GetPlugin("Ports")
	//plugin, err := securityscanner.GetPlugin("Waf")
	//plugin, err := securityscanner.GetPlugin("Wappalyzer")

	if err != nil {
		logger.LoggerError.Fatal(err)
	}
	plugin.SetArgs(&securityscanner.ScannerArgs{Domain: "www.google.pl", Protocol: "http"})
	results, err := plugin.Scan()
	if err != nil {
		logger.LoggerError.Error(err)
	}
	spew.Dump(results)
}

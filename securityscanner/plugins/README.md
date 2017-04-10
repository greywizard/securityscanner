# Security Scanner Plugins

Each plugin is placed under separated package in separate directory.

## Menu

* [List of available plugins](#list-of-available-plugins)
  * [Blacklist](#blacklist) 
  * [Files](#files)
  * [Headers](#headers)
  * [Https](#https)
  * [IP](#ip)
  * [PageSpeed](#pagespeed)
  * [Ports](#ports)
  * [Waf](#waf)
  * [Wapalyzer](#wappalyzer)
  
* [Skeleton of new plugin](#skeleton-of-new-plugin)

# List of available plugins:
## Blacklist 
Checks if the domain exists on global blacklists. Supporting **Google Safe Browsing**, **Bitdefender**, **ESET Online Scanner**, **Kaspersky**.

Configuration keys:
* **google_api_key** - API Key required for Google Safe Browsing. [Get started](https://developers.google.com/safe-browsing/v4/get-started).
* **virustotal_api_key** - API Key required for VirusTotal. [Get started](https://www.virustotal.com/en/documentation/public-api/#getting-started).

## Files
Checks if sensitive files (GIT, SVN, .htaccess) are not accessible

## Headers

Checks status of security headers in server response

## Https

Checks security of TLS/SSL protocol.

**Reqiures `nmap` installed.**

## IP

Retrieve data based on domain IP.

**Requires GeoIP database, check `.\securityscanner\plugins\ip\geoip\get.sh` 
 to download MaxMind databases**
 
Configuration keys:
 * **geo_path** - location of GeoIP Database

## PageSpeed

Retrieve data about page speed provided by Google PageSpeed Insights

Configuration keys:
* **google_api_key** - API Key required for Google Safe Browsing. [Get started](https://developers.google.com/speed/docs/insights/v1/getting_started).

## Ports

Checks which ports are open

## Waf

Checks behavior for common vulnerabilities checks like XSS, SQLinjections, executing commands on host operating system. 

This plugin only check if website allows for such calls (don't use Web Application Firewall - WAF). Don't check the vulnerability itself.

## Wapalyzer
Based on [AliasIO/Wappalyzer](https://github.com/AliasIO/Wappalyzer) uncover technologies used on webiste.

**Requires to install Docker image `wappalyzer\grey_wizard`. Run:**
 
`sh .\securityscanner\plugins\wappalyzer\Dockerfile\build.sh `

# Sleleton of new plugin:

```
package sample

import (
	"github.com/greywizard/securityscanner/securityscanner"	
)

type SamplePlugin struct {
	securityscanner.Plugin
}

func (s *SamplePlugin) Code() string {
	return s.Name()
}

func (s *SamplePlugin) Name() string {
	return "Sample"
}

func (s *SamplePlugin) Info() map[string]interface{} {
	return map[string]interface{}{}
}

func (s *SamplePlugin) Scan() (map[string]interface{}, error) {
	s.Validate()

	value := map[string]interface{}{
		"ok": "true",
	}

	return value, nil
}
```
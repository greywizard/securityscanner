package plugins

import (
	_ "github.com/greywizard/securityscanner/securityscanner/plugins/blacklist"
	_ "github.com/greywizard/securityscanner/securityscanner/plugins/files"
	_ "github.com/greywizard/securityscanner/securityscanner/plugins/headers"
	_ "github.com/greywizard/securityscanner/securityscanner/plugins/https"
	_ "github.com/greywizard/securityscanner/securityscanner/plugins/ip"
	_ "github.com/greywizard/securityscanner/securityscanner/plugins/pagespeed"
	_ "github.com/greywizard/securityscanner/securityscanner/plugins/ports"
	_ "github.com/greywizard/securityscanner/securityscanner/plugins/waf"
	_ "github.com/greywizard/securityscanner/securityscanner/plugins/wappalyzer"
)

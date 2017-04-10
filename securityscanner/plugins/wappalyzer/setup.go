package wappalyzer

import "github.com/greywizard/securityscanner/securityscanner"

func init() {
	plugin := new(WappalyzerPlugin)
	securityscanner.RegisterPlugin(plugin.Code(), plugin)
}

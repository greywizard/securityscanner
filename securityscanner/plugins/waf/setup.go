package waf

import "github.com/greywizard/securityscanner/securityscanner"

func init() {
	plugin := new(WafPlugin)
	securityscanner.RegisterPlugin(plugin.Code(), plugin)
}

package pagespeed

import "github.com/greywizard/securityscanner/securityscanner"

func init() {
	plugin := new(PagespeedPlugin)
	securityscanner.RegisterPlugin(plugin.Code(), plugin)
}

package ip

import "github.com/greywizard/securityscanner/securityscanner"

func init() {
	plugin := new(IpPlugin)
	securityscanner.RegisterPlugin(plugin.Code(), plugin)
}

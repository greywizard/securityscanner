package blacklist

import "github.com/greywizard/securityscanner/securityscanner"

func init() {
	plugin := new(BlacklistPlugin)
	securityscanner.RegisterPlugin(plugin.Code(), plugin)
}

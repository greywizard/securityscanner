package pseudo

import "github.com/greywizard/securityscanner/securityscanner"

func init() {
	plugin := new(PseudoPlugin)
	securityscanner.RegisterPlugin(plugin.Code(), plugin)
}

package ports

import "github.com/greywizard/securityscanner/securityscanner"

func init() {
	plugin := new(PortsPlugin)
	securityscanner.RegisterPlugin(plugin.Code(), plugin)
}

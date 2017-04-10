package headers

import "github.com/greywizard/securityscanner/securityscanner"

func init() {
	plugin := new(HeadersPlugin)
	securityscanner.RegisterPlugin(plugin.Code(), plugin)
}

package https

import "github.com/greywizard/securityscanner/securityscanner"

func init() {
	plugin := new(HttpsPlugin)
	securityscanner.RegisterPlugin(plugin.Code(), plugin)
}

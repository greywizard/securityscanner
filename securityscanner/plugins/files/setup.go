package files

import "github.com/greywizard/securityscanner/securityscanner"

func init() {
	plugin := new(FilesPlugin)
	securityscanner.RegisterPlugin(plugin.Code(), plugin)
}

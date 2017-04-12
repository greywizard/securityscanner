package main

import (
	"github.com/greywizard/securityscanner/securityscanner"
	_ "github.com/greywizard/securityscanner/securityscanner/plugins"
)

func main() {
	securityscanner.StartRPC()
}

package pseudo

import (
	"testing"

	"github.com/greywizard/securityscanner/securityscanner"
)

func TestPseudoPlugin_Scan(t *testing.T) {
	plugin := new(PseudoPlugin)
	plugin.SetArgs(&securityscanner.ScannerArgs{Domain: "www.google.pl", Protocol: "http"})

	val, err := plugin.Scan()
	if err != nil {
		t.Error(err)
	}
	expectedValue := map[string]interface{}{
		"ok": "true",
	}

	if _, ok := val["ok"]; !ok {
		t.Error(val)
	}

	if val["ok"] != expectedValue["ok"] {
		t.Error("Unexpected value ", val, "got", expectedValue)
	}
}

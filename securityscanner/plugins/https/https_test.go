package https

import (
	"bytes"
	"io"
	"testing"

	"os/exec"

	"github.com/greywizard/securityscanner/securityscanner"
	"github.com/greywizard/securityscanner/securityscanner/logger"
	"github.com/stretchr/testify/require"
)

var pluginName = "Https"
var pluginCode = "Https"

func TestDockerInstalled(t *testing.T) {
	cmdW := exec.Command("docker", "--version")
	err := cmdW.Run()
	require.NoError(t, err, "Docker must be installed for this plugin")
}

func TestDockerImageExists(t *testing.T) {
	imageName := "instrumentisto/nmap"
	imageExists := checkImage(imageName)
	if !imageExists {
		tryBuildImage(imageName, t)
		logger.LoggerDebug.Debug("nmap", "docker installing")
		imageExists = checkImage("instrumentisto/nmap")
	}

	require.True(t, imageExists, "Docker image \""+imageName+"\" is not installed\nRun .\\securityscanner\\plugins\\wappalyzer\\Dockerfile\\build.sh")
}

func checkImage(image string) bool {
	c1 := exec.Command("docker", "images")
	c2 := exec.Command("grep", image)

	pr, pw := io.Pipe()
	c1.Stdout = pw
	c2.Stdin = pr

	var b2 bytes.Buffer
	c2.Stdout = &b2

	c1.Start()
	c2.Start()

	go func() {
		defer pw.Close()

		c1.Wait()
	}()
	c2.Wait()
	return b2.Len() > 0
}

func tryBuildImage(image string, t *testing.T) {
	cmdW := exec.Command("docker", "image", "pull", image)
	err := cmdW.Run()
	require.NoError(t, err, "Error installing image ", image)
}

func TestHttpsPlugin_Scan(t *testing.T) {
	plugin := new(HttpsPlugin)
	plugin.SetArgs(&securityscanner.ScannerArgs{Domain: "www.google.pl", Protocol: "http"})

	val, err := plugin.Scan()
	require.NoError(t, err)

	expectedKeys := []string{"https", "poodle", "drown"}

	for _, k := range expectedKeys {
		require.Contains(t, val, k)
		require.NotEmpty(t, val[k], k)
		require.Contains(t, securityscanner.StatusColors, val[k])
	}
}

func TestHttpsPlugin_Code(t *testing.T) {
	plugin := new(HttpsPlugin)
	require.Equal(t, plugin.Code(), pluginCode)
}

func TestHttpsPlugin_Name(t *testing.T) {
	plugin := new(HttpsPlugin)
	require.Equal(t, plugin.Name(), pluginName)
}

func TestHttpsPlugin_Info(t *testing.T) {
	plugin := new(HttpsPlugin)
	val := plugin.Info()

	expectedKeys := []string{"https", "poodle", "drown"}

	for _, k := range expectedKeys {
		require.Contains(t, val, k)
	}
}

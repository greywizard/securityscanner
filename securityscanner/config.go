package securityscanner

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/spf13/viper"
)

var ErrInvalidConfigurationOption = errors.New("invalid configuration option")
var configLoaded = false

func LoadConfig() bool {
	if configLoaded {
		return false
	}

	configPath := flag.String("config", os.Getenv("GOPATH")+"/src/github.com/greywizard/securityscanner/config/config.json", "config string path")
	flag.Parse()

	viper.SetConfigType("json")
	viper.SetConfigFile(*configPath)
	err := viper.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("Fatal error config file: %s \n", err))
	}

	configLoaded = true
	return true
}
func init() {
	LoadConfig()
}

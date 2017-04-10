package securityscanner

import (
	"errors"
	"fmt"

	"github.com/spf13/viper"
)

var ErrInvalidConfigurationOption = errors.New("invalid configuration option")
var configLoaded = false

func LoadConfig() bool {
	if configLoaded {
		return false
	}

	viper.SetConfigName("config")
	viper.SetConfigType("json")
	viper.AddConfigPath("$GOPATH/src/github.com/greywizard/securityscanner/config")
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

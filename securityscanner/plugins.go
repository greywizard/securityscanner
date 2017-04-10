package securityscanner

import (
	"errors"
	"fmt"
)

var (
	plugins = make(map[string]PluginInterface)
)

type PluginInterface interface {
	Scan() (map[string]interface{}, error)
	Name() string
	Code() string
	Info() map[string]interface{}
	SetArgs(args *ScannerArgs)
}

type Plugin struct {
	PluginInterface
	*ScannerArgs
}

func (p *Plugin) SetArgs(args *ScannerArgs) {
	p.ScannerArgs = args
}

func (p *Plugin) Validate() {
	if p.ScannerArgs == nil {
		panic("Can't scan without ScannerArgs provided")
	}
}

func RegisterPlugin(name string, plugin PluginInterface) {
	if name == "" {
		panic("plugin must have a name")
	}

	if _, dup := plugins[name]; dup {
		panic("plugin named " + name + " already registered")
	}
	plugins[name] = plugin
}

func DeregisterPlugin(name string) {
	if _, plugin := plugins[name]; plugin {
		delete(plugins, name)
	}
}

func GetPlugin(name string) (plugin PluginInterface, err error) {
	for n, p := range plugins {
		if n == name {
			plugin = p
			return
		}
	}

	err = errors.New(fmt.Sprintf("Plugin \"%s\" is not registered", name))

	return
}

func GetAllPlugins() (allPlugins []PluginInterface) {
	i := 0
	allPlugins = make([]PluginInterface, len(plugins))
	for _, p := range plugins {
		allPlugins[i] = p
		i++
	}
	return allPlugins
}

/*
func DescribePlugins() string {
	str := "\nPlugins:\n"
	for _, plugin := range plugins {
		str += "  " + plugin.Code() + "\n"
	}

	return str
}
*/

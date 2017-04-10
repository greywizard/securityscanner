package ip

import (
	"net"
	"strings"
	"time"

	"github.com/abh/geoip"
	"github.com/greywizard/securityscanner/securityscanner"
	"github.com/greywizard/securityscanner/securityscanner/logger"
	"github.com/greywizard/securityscanner/securityscanner/translate"
	"github.com/spf13/viper"
)

type IpPlugin struct {
	securityscanner.Plugin
}

var geoipCounty *geoip.GeoIP
var geoipASN *geoip.GeoIP

//TODO: get IP databases script
func initConfig() error {
	var err error

	geoPath := viper.GetString("geo_path")

	geoipCounty, err = geoip.Open(geoPath + "GeoIP.dat")
	if err != nil {
		logger.LoggerError.Error(securityscanner.ErrInvalidConfigurationOption)
	}

	geoipASN, err = geoip.Open(geoPath + "GeoIPASNum.dat")
	if err != nil {
		logger.LoggerError.Error(securityscanner.ErrInvalidConfigurationOption)
	}

	return err
}

func (s *IpPlugin) Code() string {
	return s.Name()
}

func (s *IpPlugin) Name() string {
	return "IP"
}

func (s *IpPlugin) Info() map[string]interface{} {
	return map[string]interface{}{
		"ip":      translate.Translate("IP address"),
		"country": translate.Translate("Country"),
		"asn":     translate.Translate("ASN name (ISP)"),
		"txt":     translate.Translate("DNS TXT Records"),
		"mx":      translate.Translate("DNS MX Records"),
	}
}

func (s *IpPlugin) Scan() (map[string]interface{}, error) {
	s.Validate()

	defer func(start time.Time) {
		logger.LoggerDebug.Debugf("[TIME] %s/%s/%s: %s", s.Code(), s.Domain, translate.GetLang(), time.Since(start))
	}(time.Now())

	err := initConfig()
	if err != nil {
		return map[string]interface{}{}, err
	}

	logger.LoggerDebug.Debugf("[SCANNER] %s: %s", s.Code(), s.Domain)

	value := map[string]interface{}{
		"ip":      "",
		"country": "",
		"asn":     "",
		"txt":     "",
		"mx":      "",
	}

	ips, err := net.LookupIP(s.Domain)

	if err != nil {
		logger.LoggerError.Error(logger.Trace(err))
	} else {
		ipAddresses := ""
		for i, ip := range ips {
			if i > 0 {
				ipAddresses += ", "
			}
			ipAddresses += ip.String()
		}
		value["ip"] = ipAddresses
		value["asn"] = geoipASN.GetOrg(ips[0].String())
		value["country"], _ = geoipCounty.GetCountry(ips[0].String())

		if txts, err := net.LookupTXT(s.Domain); err != nil {
			logger.LoggerError.Error(logger.Trace(err))
			value["txt"] = ""
		} else {
			value["txt"] = strings.Join(txts, ", ")
		}

		if mxs, err := net.LookupMX(s.Domain); err != nil {
			logger.LoggerError.Error(logger.Trace(err))
			value["mx"] = ""
		} else {
			mxHosts := ""
			for i, mx := range mxs {
				if i > 0 {
					mxHosts += ", "
				}
				mxHosts += mx.Host
			}
			value["mx"] = mxHosts
		}
	}

	return value, nil
}

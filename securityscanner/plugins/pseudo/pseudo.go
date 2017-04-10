package pseudo

import (
	"time"

	"github.com/greywizard/securityscanner/securityscanner"
	"github.com/greywizard/securityscanner/securityscanner/logger"
	"github.com/greywizard/securityscanner/securityscanner/translate"
)

type PseudoPlugin struct {
	securityscanner.Plugin
}

func (s *PseudoPlugin) Code() string {
	return s.Name()
}

func (s *PseudoPlugin) Name() string {
	return "Pseudo"
}

func (s *PseudoPlugin) Info() map[string]interface{} {
	return map[string]interface{}{
		"ok": "Show info that is ok",
	}
}

func (s *PseudoPlugin) Scan() (map[string]interface{}, error) {
	defer func(start time.Time) {
		logger.LoggerDebug.Debugf("[TIME] %s/%s/%s: %s", s.Code(), s.Domain, translate.GetLang(), time.Since(start))
	}(time.Now())

	s.Validate()

	value := map[string]interface{}{
		"ok": "true",
	}

	return value, nil
}

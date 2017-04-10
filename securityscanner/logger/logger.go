//Package logger override logrus and set configuration paths
package logger

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/Sirupsen/logrus"
	"github.com/spf13/viper"
)

var LoggerError *logrus.Logger
var LoggerDebug *logrus.Logger

//Initialize set level of reporting and path to logged file
func Initialize() {
	LoggerError = logrus.New()
	LoggerError.Formatter = &logrus.JSONFormatter{}

	logPath := viper.GetString("log_path")

	fd, err := os.OpenFile(logPath+"securityscanner_all.log", os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0660)
	if err != nil {
		panic(err)
	}

	LoggerError.Out = fd
	LoggerError.Level = logrus.ErrorLevel

	LoggerDebug = logrus.New()
	//logger.LoggerDebug.Out = ioutil.Discard
	LoggerDebug.Out = fd //TODO replace with ioutil.Discard

	LoggerDebug.Formatter = &logrus.JSONFormatter{}
	LoggerDebug.Level = logrus.DebugLevel
}

//Trace return formatted trace of error
func Trace(err error) string {
	buf := make([]byte, 32)
	for {
		n := runtime.Stack(buf, false)
		if n < len(buf) {
			break
		}
		buf = make([]byte, len(buf)*2)
	}
	bufString := string(buf[:strings.Index(string(buf), "\x00")])
	bufString = strings.Replace(bufString, "\n", " ", -1)

	return fmt.Sprintf("%s: Stactrace: %s", err, bufString)
}

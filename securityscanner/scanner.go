//Package securityscanner checks the website for XSS, SQL Injection, blacklisting status, configuration and out-of-date software.
package securityscanner

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	_ "net/http/pprof"

	"github.com/davecgh/go-spew/spew"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/gorilla/rpc/v2"
	"github.com/gorilla/rpc/v2/json2"
	"github.com/goware/throttler"
	"github.com/greywizard/securityscanner/securityscanner/logger"
	"github.com/greywizard/securityscanner/securityscanner/translate"
	cache "github.com/pmylund/go-cache"
	"github.com/spf13/viper"
)

const (
	GREEN  = "GREEN"
	YELLOW = "YELLOW"
	RED    = "RED"
)

// Allowed status colors for tests
var StatusColors = []string{GREEN, YELLOW, RED}

type ScannerService string

type ScannerConfig interface{}

type ScannerArgs struct {
	Domain   string
	Protocol string
}

type ScannerServiceArgs struct {
	Lang    translate.Language
	Domain  string
	NoCache bool
}
type ScannerServiceResult struct {
	Scanners map[string]interface{}
	Took     float64
}

var scannerCache = cache.New(3*time.Hour, 10*time.Minute)

func init() {
	logger.Initialize()
}

//All scans requested Domain for all registered plugins
func (s *ScannerService) All(r *http.Request, args *ScannerServiceArgs, result *ScannerServiceResult) error {
	if len(args.Lang) > 0 {
		if err := translate.SetLang(args.Lang); err != nil {
			logger.LoggerError.Warning(err)
		}
	}

	lang := string(translate.GetLang())
	defer func(start time.Time) {
		logger.LoggerDebug.Debugf("[TIME] %s/%s/%s: %s", "ScannerService.All", args.Domain, lang, time.Since(start))
		result.Took = time.Since(start).Seconds()
	}(time.Now())

	cacheKey := "scan_result_" + args.Domain + "_" + lang
	if !args.NoCache {
		if val, found := scannerCache.Get(cacheKey); found {
			logger.LoggerDebug.Debugf("ALL PROBES FROM CACHE FOR: %s", args.Domain)
			result.Scanners = val.(map[string]interface{})
			return nil
		}
	}
	logger.LoggerDebug.Debugf("[SERVICE] ALL PROBES FROM CODE: %s LANG: %s", args.Domain, lang)

	//Let's check if domain is valid
	ips, err := net.LookupIP(args.Domain)
	if err != nil {
		logger.LoggerError.Error(logger.Trace(err))
		return err
	} else {
		for _, ip := range ips {
			if !ip.IsGlobalUnicast() {
				e := errors.New(fmt.Sprintf("invalid IP address %s for: %s", ip.String(), args.Domain))
				logger.LoggerError.Error(spew.Sdump(args), e)
				return e
			}
		}
	}

	protocol := "http"
	response, _, err := HttpGet("http://"+args.Domain, DefaultTimeout)
	if err != nil {
		//Can be accesible only by the  HTTPS
		protocol = "https"
		response, _, err = HttpGet("https://"+args.Domain, DefaultTimeout)
		if err != nil {
			logger.LoggerError.Error(spew.Sdump(args), logger.Trace(err))
			return err
		}
	}

	if strings.Contains(response.Request.URL.String(), "127.0.0.1") || strings.Contains(response.Request.URL.String(), "localhost") {
		return errors.New(fmt.Sprintf("uri %s points to localhost", response.Request.URL.String()))
	}

	scannerConstructor := &ScannerArgs{Domain: args.Domain, Protocol: protocol}
	plugins := GetAllPlugins()
	if len(plugins) == 0 {
		logger.LoggerError.Warning("There are no plugins registered")
	}

	wg := new(sync.WaitGroup)
	var mutex = new(sync.Mutex)

	value := map[string]interface{}{}
	for _, p := range plugins {
		wg.Add(1)
		go func(plugin PluginInterface) {
			defer wg.Done()
			plugin.SetArgs(scannerConstructor)
			result, err := plugin.Scan()

			errorMessage := ""
			if err != nil {
				logger.LoggerError.Errorf("%s: %s: ", plugin.Code(), logger.Trace(err))
				errorMessage = err.Error()
			}

			mutex.Lock()
			value[plugin.Code()] = struct {
				Name   string
				Info   map[string]interface{}
				Result map[string]interface{}
				Error  string
			}{
				Name:   plugin.Name(),
				Info:   plugin.Info(),
				Result: result,
				Error:  errorMessage,
			}

			mutex.Unlock()
		}(p)
	}
	wg.Wait()

	result.Scanners = value
	scannerCache.Set(cacheKey, value, 0)
	return nil
}

//StartRPC runs JSON RPC server listening for scan requests
func StartRPC() {
	s := rpc.NewServer()
	s.RegisterCodec(json2.NewCodec(), "application/json")
	s.RegisterCodec(json2.NewCodec(), "application/json;charset=UTF-8")
	service := new(ScannerService)
	err := s.RegisterService(service, "")
	if err != nil {
		panic(err)
	}

	throttle := viper.GetInt("throttle")
	serverPort := viper.GetInt("server_port")
	limit := throttler.Limit(throttle)
	r := mux.NewRouter()
	r.PathPrefix("/debug/pprof/").Handler(http.DefaultServeMux)
	r.Handle("/", limit(s))
	logger.LoggerDebug.Debugf("[SERVICE] Starting RPC on port: %d with profiler at: %s", serverPort, "/debug/pprof/")

	logPath := viper.GetString("log_path")
	logFile, err := os.OpenFile(logPath+"probes.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		panic(err)
	}
	if err = http.ListenAndServe(fmt.Sprintf(":%d", serverPort), handlers.CompressHandler(handlers.LoggingHandler(logFile, r))); err != nil {
		logger.LoggerError.Error(logger.Trace(err))
		panic(err)
	}
}

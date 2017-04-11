package https

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/greywizard/securityscanner/securityscanner"
	"github.com/greywizard/securityscanner/securityscanner/logger"
	"github.com/greywizard/securityscanner/securityscanner/translate"
)

type HttpsPlugin struct {
	securityscanner.Plugin
}

func (s *HttpsPlugin) Code() string {
	return s.Name()
}

func (s *HttpsPlugin) Name() string {
	return "Https"
}

func (s *HttpsPlugin) Info() map[string]interface{} {
	return map[string]interface{}{
		"https":  translate.Translate("The primary goal of the TLS/SSL protocol is to provide privacy and data integrity between two communicating computer applications. Client-server applications use the TLS/SSL protocol to communicate across a network in a way designed to prevent eavesdropping and tampering."),
		"poodle": translate.Translate("`POODLE` attack allows an active MITM attacker to decrypt content transferred an SSLv3 connection."),
		"drown":  translate.Translate("`DROWN` allows attackers to break the encryption and read or steal sensitive communications, including passwords, credit card numbers, trade secrets, or financial data."),
	}
}

func (s *HttpsPlugin) Scan() (map[string]interface{}, error) {
	s.Validate()

	defer func(start time.Time) {
		logger.LoggerDebug.Debugf("[TIME] %s/%s/%s: %s", s.Code(), s.Domain, translate.GetLang(), time.Since(start))
	}(time.Now())

	logger.LoggerDebug.Debugf("[SCANNER] %s: %s", s.Code(), s.Domain)
	//HTTP2.0 check:
	//https://github.com/golang/go/issues/14391
	//response, _ := http.Get("https://http2.golang.org/reqinfo")
	//fmt.Printf("is HTTP2: %v (%s)\n\n", response.ProtoAtLeast(2, 0), response.Proto)

	//The http package has transparent support for the HTTP/2 protocol when using HTTPS.
	// Programs that must disable HTTP/2 can do so by setting Transport.TLSNextProto (for clients) or Server.TLSNextProto (for servers) to a non-nil, empty map.
	// Alternatively, the following GODEBUG environment variables are currently supported:
	//GODEBUG=http2client=0  # disable HTTP/2 client support
	//for go 1.7 http2 can be enabled

	value := map[string]interface{}{"https": securityscanner.GREEN}

	response, _, err := securityscanner.HttpGet("https://"+s.Domain, securityscanner.DefaultTimeout)
	if err != nil {
		value["https"] = securityscanner.RED
	} else {
		if strings.Index(response.Request.URL.String(), "https://") < 0 {
			value["https"] = securityscanner.RED
		}
	}
	if value["https"] == securityscanner.GREEN {
		if response, _, err := securityscanner.HttpGet("http://"+s.Domain, securityscanner.DefaultTimeout); err == nil {
			if strings.Index(response.Request.URL.String(), "https://") < 0 {
				value["https"] = securityscanner.YELLOW
			}
		}
	}

	if value["https"] != securityscanner.RED {
		wg := new(sync.WaitGroup)
		var mutex = new(sync.Mutex)
		wg.Add(1)
		go func() {
			defer wg.Done()
			command := exec.Command("docker", "run", "--rm", "instrumentisto/nmap", "-T5", "-P0", "--script", "ssl-poodle.nse", "-p", "443", s.Domain)
			if status, err := checkStatus("POODLE", command, s.Domain, "CVE-2014-3566"); err != nil {
				logger.LoggerError.Error(logger.Trace(err))
			} else {
				mutex.Lock()
				value["poodle"] = status
				mutex.Unlock()
			}
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			command := exec.Command("docker", "run", "--rm", "instrumentisto/nmap", "-T5", "-P0", "--script", "sslv2.nse", "-p", "443", s.Domain)

			if status, err := checkStatus("V2", command, s.Domain, "SSLv2 supported"); err != nil {
				logger.LoggerError.Error(logger.Trace(err))
			} else {
				mutex.Lock()
				value["drown"] = status
				mutex.Unlock()
			}
		}()
		wg.Wait()
	}

	return value, nil
}

func checkStatus(name string, command *exec.Cmd, domain string, expectedSring string) (color string, err error) {
	logger.LoggerDebug.Debug("[SCANNER] HTTPS "+name+" START: ", domain)

	var outW bytes.Buffer
	envW := os.Environ()
	command.Env = envW
	command.Stdout = &outW
	command.Stderr = &outW

	if err := command.Start(); err != nil {
		return "", err
	}
	timer := time.AfterFunc(securityscanner.DefaultTimeout, func() {
		logger.LoggerError.Error("nmap timeout")
		_ = command.Process.Kill()
	})
	defer timer.Stop()

	if err := command.Wait(); err != nil {
		logger.LoggerError.Error("nmap: ", outW.String())
		return "", err
	}

	logger.LoggerDebug.Debug("[SCANNER] NMAP POODLE STOP: ", domain, outW.String())

	if strings.Contains(outW.String(), expectedSring) {
		return securityscanner.RED, nil
	}
	return securityscanner.GREEN, nil
}

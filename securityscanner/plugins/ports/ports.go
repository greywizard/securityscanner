package ports

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/greywizard/securityscanner/securityscanner"
	"github.com/greywizard/securityscanner/securityscanner/logger"
	"github.com/greywizard/securityscanner/securityscanner/translate"
)

type PortsPlugin struct {
	securityscanner.Plugin
}

var portsToCheck = map[int]string{
	21:    "FTP",
	23:    "Telnet",
	25:    "SMTP",
	66:    "Oracle SQL",
	69:    "TFTP",
	88:    "Kerberos",
	109:   "POP2",
	110:   "POP3",
	118:   "SQL service",
	123:   "NTP",
	137:   "Netbios",
	139:   "Netbios",
	194:   "IRC",
	445:   "Samba",
	150:   "SQL-net",
	554:   "RTSP",
	547:   "DHCP Server",
	631:   "Cups",
	1433:  "Microsoft SQL server",
	1434:  "Microsoft SQL monitor",
	3306:  "MySQL",
	3396:  "Novell NDPS Printer Agent",
	3535:  "SMTP (alternate)",
	5432:  "Postgresql",
	5800:  "VNC remote desktop",
	8080:  "HTTP Proxy",
	9160:  "Cassandra",
	9200:  "Elasticsearch",
	27017: "MongoDB",
	28017: "MongoDB admin",
}

func (s *PortsPlugin) Info() map[string]interface{} {
	info := map[string]interface{}{}
	for k, v := range portsToCheck {
		info[fmt.Sprintf("%d", k)] = v
	}
	return info
}

func (s *PortsPlugin) Code() string {
	return "Ports"
}

func (s *PortsPlugin) Name() string {
	return translate.Translate("Opened ports")
}

func (s *PortsPlugin) Scan() (map[string]interface{}, error) {
	s.Validate()

	defer func(start time.Time) {
		logger.LoggerDebug.Debugf("[TIME] %s/%s/%s: %s", s.Code(), s.Domain, translate.GetLang(), time.Since(start))
	}(time.Now())

	logger.LoggerDebug.Debugf("[SCANNER] %s: %s", s.Code(), s.Domain)

	value := map[string]interface{}{}
	wg := new(sync.WaitGroup)
	var mutex = new(sync.Mutex)

	for port, _ := range portsToCheck {
		wg.Add(1)
		mutex.Lock()
		value[fmt.Sprintf("%d", port)] = securityscanner.GREEN
		mutex.Unlock()
		go func(p int) {
			defer wg.Done()
			tcpAddr, err := net.ResolveTCPAddr("tcp4", fmt.Sprintf("%s:%d", s.Domain, p))
			if err != nil {
				logger.LoggerError.Error(logger.Trace(err))
				return
			}

			conn, err := net.DialTimeout("tcp", tcpAddr.String(), 3*time.Second)
			if err == nil {
				mutex.Lock()
				value[fmt.Sprintf("%d", p)] = securityscanner.YELLOW
				mutex.Unlock()
			}

			if conn != nil {
				conn.Close()
			}
		}(port)
	}

	wg.Wait()

	return value, nil
}

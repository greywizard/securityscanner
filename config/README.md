#Config files

Example structure of `config_sample.json`:

```
{
  "log_path": "/tmp/", 
  "geo_path": "/usr/local/share/GeoIP/",
  "google_api_key": "xxxxx",
  "virustotal_api_key": "xxxxx",
  "pagespeed_api_key": "xxxx",
  "bot_name": "Mozilla/5.0 (compatibile; SecurityScanner BOT)",
  "server_port": "1234",
  "is_local": true,
  "throttle": "15"
}
```

Explanations of fields

* **log_path** - location where logs are stored
* **geo_path** - location of [GeoIP](/securityscanner/plugins/README.md#ip) Database
* **google_api_key** - API Key required for [Blacklist plugin](/securityscanner/plugins/README.md#blacklist)
* **virustotal_api_key** - API Key required for [Blacklist plugin](/securityscanner/plugins/README.md#blacklist)
* **pagespeed_api_key** - API Key required for [Pagespeed plugin](/securityscanner/plugins/README.md#pagespeed) 
* **bot_name** - User Agent of Security Scanner
* **server_port** - Server port on which JSON RPC server will be running
* **is_local** - Define if it is local environment
* **throttle** - Limit of concurrent processed requests by JSON RPC server at the same time
 


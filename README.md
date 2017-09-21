# Security Scanner by Grey Wizard

Security Scanner checks the website for XSS, SQL Injection, blacklisting status, configuration and out-of-date software. 
Following the guidelines contained in the report will significantly increase the security of your site and protect against DDoS attacks. 
Scanner is a free & usually safe for tested webpage. 


With plugin based structure can be easy upgraded with other rules and checks.  

## Menu

- [Configuration](#configuration)
- [Plugin dependencies](#plugin-dependencies)
- [Run as JSON RPC Server](#run-as-json-rpc-server)
- [Running simple plugin](#running-simple-plugin)
- [Plugins](#plugins)
- [Building in docker](#building-in-docker)


## Configuration

Scanner is requiring the config file in `config/config.json` path.

Config file can be overriden with `-config=/full/path/to/config.json` flag

Check the [README](config/) file for example config


To check if all required fields dependent by plugins are set in configuration:

`make check-configuration`

## Plugin dependencies

To check if all required dependencies (like geoip databases, docker images) are installed run:

`make check-dependencies`

## Run as JSON RPC Server:

Run:

`go run cmd/scannerServer.go`

example of request:

`http -p=Hh -jv localhost:1234/ method=ScannerService.All params:='[{"Domain": "example.com", "Lang": "en"}]' id=$RANDOM jsonrpc=2.0`

or

`curl --data-binary '{"jsonrpc":"2.0","id":"curltext","method":"ScannerService.All","params":[{"Domain": "example.com", "Lang": "en", "Nocache": true}]}' -H 'Content-Type:application/json;' http://127.0.0.1:1234`

# Running simple plugin:

Check [cmd/scanner.go](cmd/scanner.go) source code


# Running tests:

`make test` run all unit tests

`make test-xml` run tests with xUnit output

`make test-coverage` calculate tests coverage

# Plugins
 
Go to [README](securityscanner/plugins/) for more info

# Build

To build using go installed in OS run:
```
make build
```

Output goes to `bin/` directory

# Building in docker

To build program using docker image (based on [https://hub.docker.com/_/golang/](https://hub.docker.com/_/golang/)) use:
```
cd docker
docker build -t golang:1.8.1-securityscanner .
cd ..
docker run --rm -v "$PWD":/usr/local/go/src/github.com/greywizard/securityscanner -w /usr/local/go/src/github.com/greywizard/securityscanner golang:1.8.1-securityscanner go build -v cmd/scannerServer.go
```


 

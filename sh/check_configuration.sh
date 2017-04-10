#!/usr/bin/env bash
go test ./securityscanner/plugins/blacklist -run TestBlacklistPlugin_Configuration
go test ./securityscanner/plugins/ip -run TestIpPlugin_Configuration
go test ./securityscanner/plugins/pagespeed -run TestPagespeedPlugin_Configuration
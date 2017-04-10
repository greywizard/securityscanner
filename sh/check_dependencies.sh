#!/usr/bin/env bash
go test ./securityscanner/plugins/ip -run TestIpPlugin_CheckDatabase
go test ./securityscanner/plugins/wappalyzer -run TestDockerImageExists
go test ./securityscanner/plugins/https -run TestNmapAvailable
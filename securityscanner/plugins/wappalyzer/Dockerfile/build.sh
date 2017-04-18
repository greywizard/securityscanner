#!/usr/bin/env bash
cd "${0%/*}"
docker build -t wappalyzer/grey_wizard .

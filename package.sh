#!/bin/bash
mkdir pkg >/dev/null 2>&1

docker build -f Dockerfile.lambda -t dnsmonitor-lambda .
docker run -it --rm \
  --mount src="${PWD}/pkg/",target='/output',type=bind \
  dnsmonitor-lambda
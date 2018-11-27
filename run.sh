#!/bin/bash
source creds.env
docker run -it --rm \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  -e AWS_SESSION_TOKEN \
  -e CF_API_EMAIL \
  -e CF_API_KEY \
  -e SLACK_WEBHOOK \
  dnsmonitor $* 
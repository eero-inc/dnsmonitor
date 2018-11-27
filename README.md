DNS Monitor
===========

This is a monitoring script that is designed to help answer the following the
questions:

* Do we have domains expiring soon?
* Did someone make a change without telling anyone?
* Did our DNS get compromised?

In case a change is detected, send out notifications.

Requirements
------------

The code needs a place to save state so it can make changes. By default, the
lambda will save to the s3 bucket and object path specified in the environment
variables `AWS_BUCKET_NAME` and `AWS_OBJECT_PATH` respectively.

Build
-----

To build the docker container, just run `./build.sh` - this will require you to
manage the dnsmonitor.json between runs.

To package for lambda, run `./package.sh` instead

Running
-------

To run the container, just run `run.sh`, ensuring all your environment variables
are set. See `creds.env.example` for a demo. Or copy it to `creds.env` and edit

Also, any environment variables that end in `_ENC` will be KMS decrypted by the
role the lambda is running as. This is a feature for convenient credential
management.

Environment Variables
---------------------

The following environment variables are used by the application:

Cloudflare API credentials (Cloudflare only scanned if these are set)

* `CF_API_EMAIL`
* `CF_API_KEY`

 AWS API Credentials (AWS Route53 only scanned if these are set)

* `AWS_ACCESS_KEY_ID`
* `AWS_SECRET_ACCESS_KEY`
* `AWS_SESSION_TOKEN`

 Save to S3 Bucket (required by lambda built zip)

* `AWS_BUCKET_NAME`
* `AWS_OBJECT_PATH`

Submit changes to slack (optional)

* `SLACK_WEBHOOK`

Submit changes to sumologic (optional)

* `SUMO_HTTP_ENDPOINT`

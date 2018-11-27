#!/usr/bin/env python3
import dnsmonitor
import json
import os
from base64 import b64decode
import boto3
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def decrypt_environment(env=os.environ):
    kms = boto3.client("kms")
    for item in env.copy().keys():
        if item.endswith("_ENC"):
            print("Decrypting %s as %s:" % (item, item[:-4]))
            env[item[:-4]] = kms.decrypt(CiphertextBlob=b64decode(env[item]))[
                "Plaintext"
            ].decode("utf-8")


def lambda_handler(event, context):
    logger.info("Starting lambda...")
    # Decrypt encrypted environment vars
    env = os.environ.copy()
    decrypt_environment(env)

    new = dnsmonitor.DNSMonitor(env=env)
    new.run()

    old = dnsmonitor.DNSMonitor(env=env)
    try:
        old.load_from_s3(os.environ["AWS_BUCKET_NAME"], os.environ["AWS_OBJECT_PATH"])
    except:
        logging.error("Old dns file not found for lambda")
        old = new

    new.save_to_s3(os.environ["AWS_BUCKET_NAME"], os.environ["AWS_OBJECT_PATH"])

    # Check for changes
    differ = dnsmonitor.DNSMonitor_diff(new=new, old=old, env=env)
    differ.run()

    # Ship out the info!
    if os.environ.get("SUMO_HTTP_ENDPOINT") is not None:
        differ.to_sumologic()
    if os.environ.get("SLACK_WEBHOOK") is not None:
        differ.to_slack()

    print("Lambda done!")
    return None


def main():
    new = dnsmonitor.DNSMonitor()
    new.run()
    old = dnsmonitor.DNSMonitor()
    old.load_from_file("dnsmonitor.json")

    # Check for changes
    differ = dnsmonitor.DNSMonitor_diff(new=new, old=old)
    differ.run()

    # Debug output
    for change in differ.changes:
        j = json.loads(change)
        print(j)

    # Ship out the info!
    if os.environ.get("SUMO_HTTP_ENDPOINT") is not None:
        differ.to_sumologic()
    if os.environ.get("SLACK_WEBHOOK") is not None:
        differ.to_slack()

    # Save this run
    new.save_to_file("dnsmonitor.json")


if __name__ == "__main__":
    main()

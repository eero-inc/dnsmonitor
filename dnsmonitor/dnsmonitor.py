import sys

sys.path.insert(0, "..")

import boto3
from subprocess import check_output
import CloudFlare
import json
from time import sleep
from sortedcontainers import SortedList, SortedDict, SortedSet
import os
from .whois import NICClient
import traceback
import logging

logger = logging.getLogger()


class DNSMonitorJSONEncoder(json.JSONEncoder):
    def default(self, obj):  # pylint: disable=E0202
        if isinstance(obj, SortedSet):
            l = list(obj)
            l.sort()
            return l
        elif isinstance(obj, set):
            l = list(obj)
            l.sort()
            return l
        else:
            return super().default(obj)


class InvalidDNSRecord(LookupError):
    pass


class DNSMonitor:
    """Scrape together all our DNS stuff so we can analyze it and find differences"""

    public_zones = SortedSet()
    public_zones_aws = SortedSet()
    public_zones_cloudflare = SortedSet()
    private_zones = SortedSet()
    private_zones_aws = SortedSet()
    whois = SortedDict()
    public_records_aws = SortedDict()
    public_records_cloudflare = SortedDict()
    private_records_aws = SortedDict()

    def __init__(self, env=os.environ):
        self.env = env

    def save(self):
        """Serialize the data"""
        o = {
            "public_zones": self.public_zones,
            "public_zones_aws": self.public_zones_aws,
            "public_zones_cloudflare": self.public_zones_cloudflare,
            "private_zones": self.private_zones,
            "private_zones_aws": self.private_zones_aws,
            "whois": self.whois,
            "public_records_aws": self.public_records_aws,
            "public_records_cloudflare": self.public_records_cloudflare,
            "private_records_aws": self.private_records_aws,
        }
        return o

    def save_to_file(self, filename="dnsmonitor.json"):
        data_json = json.dumps(self.save(), indent=4, cls=DNSMonitorJSONEncoder)
        with open(filename, "w") as fh:
            fh.write(data_json)

    def save_to_s3(self, bucket, obj):
        filename = "/tmp/%s" % "dnsmonitor.json"
        self.save_to_file(filename)
        # Save to s3
        s3 = boto3.resource(
            "s3",
            aws_access_key_id=self.env["AWS_ACCESS_KEY_ID"],
            aws_secret_access_key=self.env["AWS_SECRET_ACCESS_KEY"],
            aws_session_token=self.env["AWS_SESSION_TOKEN"],
        )
        s3.meta.client.upload_file(filename, bucket, obj)
        # Cleanup
        os.remove(filename)

    def load(self, data):
        """Deserialize the data"""
        self.public_zones = SortedSet(data["public_zones"])
        self.public_zones_aws = SortedSet(data["public_zones_aws"])
        self.public_zones_cloudflare = SortedSet(data["public_zones_cloudflare"])
        self.private_zones = SortedSet(data["private_zones"])
        self.private_zones_aws = SortedSet(data["private_zones_aws"])
        self.whois = SortedDict(data["whois"])
        self.public_records_aws = SortedDict()
        for k in data["public_records_aws"]:
            self.public_records_aws[k] = SortedSet(data["public_records_aws"][k])
        self.public_records_cloudflare = SortedDict()
        for k in data["public_records_cloudflare"]:
            self.public_records_cloudflare[k] = SortedSet(
                data["public_records_cloudflare"][k]
            )
        self.private_records_aws = SortedDict()
        for k in data["private_records_aws"]:
            self.private_records_aws[k] = SortedSet(data["private_records_aws"][k])

    def load_from_file(self, filename="dnsmonitor.json"):
        with open(filename, "r") as fh:
            data = json.load(fh)
        self.load(data)

    def load_from_s3(self, bucket, obj):
        filename = "/tmp/%s.old" % "dnsmonitor.json"
        s3 = boto3.resource(
            "s3",
            aws_access_key_id=self.env["AWS_ACCESS_KEY_ID"],
            aws_secret_access_key=self.env["AWS_SECRET_ACCESS_KEY"],
            aws_session_token=self.env["AWS_SESSION_TOKEN"],
        )
        s3.meta.client.download_file(bucket, obj, filename)
        self.load_from_file(filename)
        # Cleanup
        os.remove(filename)

    def run(self, whois=True, records=True):
        """Reset the public and private zones and update via APIs"""
        # Reset zones
        self.public_zones = set()
        self.private_zones = set()
        # Fetch from various providers
        if "AWS_ACCESS_KEY_ID" in self.env:
            self.__fetch_aws(records)
        if "CF_API_KEY" in self.env:
            self.__fetch_cloudflare(records)
        if whois:
            for zone in self.public_zones:
                self.__fetch_whois(zone)

    def __fetch_whois(self, zone):
        try:
            flags = 0
            options = {}
            nic_client = NICClient()
            whois = nic_client.whois_lookup(options, zone, flags)
            clean_whois = str(whois).replace("\\r", "\r").replace("\\n", "\n")
            self.whois[zone] = clean_whois
        except Exception:
            logging.error("Exception looking up zone: %s" % zone)
            logging.error("-" * 60)
            traceback.print_exc(file=sys.stdout)
            logging.error("-" * 60)
            self.whois[zone] = "LOOKUP FAIL"

    def __fetch_cloudflare(self, records):
        """
        Connect to Cloudflare via their API and scrape data 
        This autodetects credentials from the environment or ~/.cloudflare
        """
        cf = CloudFlare.CloudFlare(
            email=self.env["CF_API_EMAIL"], token=self.env["CF_API_KEY"]
        )
        zones = cf.zones.get()  # pylint: disable=E1101
        for zone in zones:
            self.public_zones.add(zone["name"])
            self.public_zones_cloudflare.add(zone["name"])
            self.__get_cloudflare_records(cf, zone)

    def __get_cloudflare_records(self, cf, zone, private=False):
        for record in cf.zones.dns_records.get(zone["id"]):
            self.save_cloudflare_record(
                zone=zone["name"],
                dnsname=record["name"],
                target=record["content"],
                ttl=record["ttl"],
                dnstype=record["type"],
                private=private,
            )

    def __fetch_aws(self, records):
        """
        Connect to AWS Route53 via their API and scrape data 
        This autodetects credentials from the environment or ~/.aws
        """
        # List zones
        r53 = boto3.client(
            "route53",
            aws_access_key_id=self.env["AWS_ACCESS_KEY_ID"],
            aws_secret_access_key=self.env["AWS_SECRET_ACCESS_KEY"],
            aws_session_token=self.env["AWS_SESSION_TOKEN"],
        )
        lhz = r53.list_hosted_zones()
        # Split into public and private
        for zone in lhz["HostedZones"]:
            name = zone["Name"].rstrip(".")
            if zone["Config"]["PrivateZone"]:
                self.private_zones.add(name)
                self.private_zones_aws.add(name)
                self.__get_aws_records(r53, zone["Id"], name, private=True)
            else:
                self.public_zones.add(name)
                self.public_zones_aws.add(name)
                self.__get_aws_records(r53, zone["Id"], name, private=False)

    def __get_aws_records(self, r53, zone, zonename, private=False):
        paginator = r53.get_paginator("list_resource_record_sets")
        page_iterator = paginator.paginate(HostedZoneId=zone)
        for page in page_iterator:
            for record in page["ResourceRecordSets"]:
                self.__parse_aws_record(zonename, record, private)

    def __parse_aws_record(self, zone, record, private=False):
        ttl = ""
        if "TTL" in record:
            ttl = record["TTL"]
        if "AliasTarget" in record:
            self.save_aws_record(
                zone=zone,
                dnsname=record["Name"],
                target=record["AliasTarget"]["DNSName"],
                ttl=ttl,
                dnstype=record["Type"],
                private=private,
            )
        elif "ResourceRecords" in record:
            for x in record["ResourceRecords"]:
                self.save_aws_record(
                    zone=zone,
                    dnsname=record["Name"],
                    target=x["Value"],
                    ttl=ttl,
                    dnstype=record["Type"],
                    private=private,
                )
        else:
            raise InvalidDNSRecord(zone, record)

    # ##########################################################################
    def save_aws_record(self, zone, dnsname, dnstype, target, ttl="", private=False):
        dnsentry = "%s %s IN %s %s" % (dnsname, ttl, dnstype, target)
        if private:
            self.__save_private_records_aws(zone, dnsentry)
        else:
            self.__save_public_records_aws(zone, dnsentry)

    def save_cloudflare_record(
        self, zone, dnsname, dnstype, target, ttl="", private=False
    ):
        dnsentry = "%s. %s IN %s %s" % (dnsname, ttl, dnstype, target)
        if private:
            # fail, no private records in cloudflare
            pass
        else:
            self.__save_public_records_cloudflare(zone, dnsentry)

    def __save_private_records_aws(self, zone, dnsentry):
        if zone not in self.private_records_aws:
            self.private_records_aws[zone] = SortedList()
        self.private_records_aws[zone].add(dnsentry)

    def __save_public_records_aws(self, zone, dnsentry):
        if zone not in self.public_records_aws:
            self.public_records_aws[zone] = SortedList()
        self.public_records_aws[zone].add(dnsentry)

    def __save_public_records_cloudflare(self, zone, dnsentry):
        if zone not in self.public_records_cloudflare:
            self.public_records_cloudflare[zone] = SortedList()
        self.public_records_cloudflare[zone].add(dnsentry)

import sys

sys.path.insert(0, "..")

import json
from difflib import unified_diff
import uuid
from .to_slack import To_Slack
from .to_sumologic import To_Sumologic
import os


class DNSMonitor_diff:
    def __init__(self, new, old, env=os.environ):
        self.new = new
        self.old = old
        self.changes = []
        self.env = env

    def log_change(self, service, diff, old, new):
        """Update log"""
        # Generate a random ID to make searching for log changes easier
        changeid = str(uuid.uuid4())
        cdict = {
            "id": changeid,
            "service": service,
            "diff": diff,
            "oldstate": old,
            "newstate": new,
        }
        self.changes.append(json.dumps(cdict))

    def run(self):
        """Compare the old and new, and display differences"""
        self.diff_zones()
        self.diff_whois()
        self.diff_records()

    def diff(self, service, old, new):
        mydiff = []
        for line in unified_diff(
            new, old, fromfile="%s - before" % service, tofile="%s - after" % service
        ):
            if not line.startswith(
                (" ", "@@", "+++", "---", "->>>", "+>>>", "+% WHOIS", "-% WHOIS")
            ):
                mydiff.append(line.rstrip())
        if mydiff:
            self.log_change(service, "\n".join(mydiff), old, new)

    def diff_zones(self):
        self.diff_public_zones_aws()
        self.diff_public_zones_cloudflare()
        self.diff_private_zones_aws()

    def diff_public_zones_aws(self):
        if self.new.public_zones_aws != self.old.public_zones_aws:
            self.diff(
                "Public Zone created/deleted in AWS",
                list(self.old.public_zones_aws),
                list(self.new.public_zones_aws),
            )

    def diff_public_zones_cloudflare(self):
        if self.new.public_zones_cloudflare != self.old.public_zones_cloudflare:
            self.diff(
                "Public Zone created/deleted in Cloudflare",
                list(self.old.publipublic_zones_cloudflarec_zones),
                list(self.new.public_zones_cloudflare),
            )

    def diff_private_zones_aws(self):
        if self.new.private_zones_aws != self.old.private_zones_aws:
            self.diff(
                "Private Zone created/deleted in AWS",
                list(self.old.private_zones_aws),
                list(self.new.private_zones_aws),
            )

    def diff_whois(self):
        service = "WHOIS - %s"
        for domain, whois in self.new.whois.items():
            if whois != self.old.whois[domain]:
                if whois == "LOOKUP FAIL" or self.old.whois[domain] == "LOOKUP FAIL":
                    pass
                else:
                    self.diff(
                        service % domain,
                        whois.split("\n"),
                        self.old.whois[domain].split("\n"),
                    )

    def diff_records(self):
        self.diff_public_records_aws()
        self.diff_public_records_cloudflare()
        self.diff_private_records_aws()

    def diff_public_records_aws(self):
        service = "AWS DNS Record Change (Public) - %s"
        # Account for deleted domain
        for domain, _ in self.old.public_records_aws.items():
            if domain not in self.new.public_records_aws:
                self.new.public_records_aws[domain] = []
        for domain, records in self.new.public_records_aws.items():
            # Account for new domain
            if domain not in self.old.public_records_aws:
                self.old.public_records_aws[domain] = []
            # Account for changed/added/removed entries
            if domain != self.old.public_records_aws[domain]:
                self.diff(
                    service % domain,
                    list(records),
                    list(self.old.public_records_aws[domain]),
                )

    def diff_public_records_cloudflare(self):
        service = "Cloudflare DNS Record Change (Public) - %s"
        # Account for deleted domain
        for domain, _ in self.old.public_records_cloudflare.items():
            if domain not in self.new.public_records_cloudflare:
                self.new.public_records_cloudflare[domain] = []
        for domain, records in self.new.public_records_cloudflare.items():
            if domain not in self.old.public_records_cloudflare:
                self.old.public_records_cloudflare[domain] = []
            if domain != self.old.public_records_cloudflare[domain]:
                self.diff(
                    service % domain,
                    list(records),
                    list(self.old.public_records_cloudflare[domain]),
                )

    def diff_private_records_aws(self):
        service = "AWS DNS Record Change (Private) - %s"
        # Account for deleted domain
        for domain, _ in self.old.private_records_aws.items():
            if domain not in self.new.private_records_aws:
                self.new.private_records_aws[domain] = []
        for domain, records in self.new.private_records_aws.items():
            if domain not in self.old.private_records_aws:
                self.old.private_records_aws[domain] = []
            if domain != self.old.private_records_aws[domain]:
                self.diff(
                    service % domain,
                    list(records),
                    list(self.old.private_records_aws[domain]),
                )

    def to_slack(self):
        To_Slack(self.changes, env=self.env)

    def to_sumologic(self):
        To_Sumologic(self.changes, env=self.env)

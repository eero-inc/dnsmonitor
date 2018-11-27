import sys

sys.path.insert(0, "..")

import os
from datetime import datetime
import requests
import json
from urllib.parse import quote


class To_Slack:
    def __init__(self, changes, env=os.environ):
        self.changes = changes
        self.webhook = env["SLACK_WEBHOOK"]
        self.run()

    def run(self):
        # Post messages
        for c in self.changes:
            c = json.loads(c)
            url = "https://service.us2.sumologic.com/ui/index.html#section/search/@%i,%i@%s"
            start = int(datetime.now().strftime("%s")) - (5 * 60)
            end = int(datetime.now().strftime("%s")) + (30)
            query = '_sourceHost="dnsmonitor" AND "%s"' % c["id"]
            q = quote(query)
            url = url % (start * 1000, end * 1000, q)
            msg = "*%s*\n\n<%s|Full output in sumologic>\n```%s```" % (
                c["service"],
                url,
                c["diff"],
            )
            self.to_webhook(msg)

    def to_webhook(self, msg):
        requests.post(self.webhook, data=json.dumps({"text": msg}))

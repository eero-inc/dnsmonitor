import sys

sys.path.insert(0, "..")

import os
from datetime import datetime
import requests
import json
import calendar
from time import gmtime, strftime


class To_Sumologic:
    def __init__(self, changes, env=os.environ):
        self.changes = changes
        self.endpoint = env["SUMO_HTTP_ENDPOINT"]
        self.run()

    def getTimeStamp(self):
        timeStamp = strftime("%Y-%m-%d %H:%M:%S", gmtime())
        timeStamp += "Z"
        return timeStamp

    def run(self):
        for c in self.changes:
            headers = {"Content-Type": "application/json", "Accept": "application/json"}
            requests.post(self.endpoint, headers=headers, data=c)

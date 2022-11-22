#!/usr/lib/python

"""auth.py: Authenticate to Salesforce using the JWT flow."""

__author__ = "Hans Liss"
__copyright__ = "Copyright 2022, Hans Liss"
__license__ = "BSD 2-Clause License"
__version__ = "1.0"
__maintainer__ = "Hans Liss"
__email__ = "Hans@Liss.nu"
__status__ = "Example code"

import urllib.parse
import time
import json
import base64
import hashlib
import requests
import pprint
import configparser
import argparse
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import utils

def auth(client_id, username, loginURL, keyfile, authURL):

    body = 'grant_type=' + "urn:ietf:params:oauth:grant-type:jwt-bearer"

    header = {
        "alg": "RS256"
    }

    payload = {
        "iss": client_id,
        "sub": username,
        "aud": loginURL,
        "exp": int(time.time()) + 5 * 60
    }
    
    
    toSign = base64.urlsafe_b64encode(json.dumps(header).encode('latin1')).decode('latin1')
    toSign += "." + base64.urlsafe_b64encode(json.dumps(payload).encode('latin1')).decode('latin1')
    
    with open(keyfile, "r") as f:
        privkey = serialization.load_pem_private_key(f.read().encode('latin1'), password=None, backend=default_backend())
        
    sig = privkey.sign(hashlib.sha256(toSign.encode('latin1')).digest(),padding.PKCS1v15(),utils.Prehashed(hashes.SHA256()))
        
        
    body += "&assertion=" + urllib.parse.quote(toSign) + "." + urllib.parse.quote(base64.urlsafe_b64encode(sig).decode('latin1'))
    
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    result = requests.post(authURL, data=body.encode('latin1'), headers=headers)
    
    if result.status_code != 200:
        print("Error: " + result.status_code + " : " + result.reason)
        return None
    else:
        authInfo=json.loads(result.text)
        return authInfo

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Authenticate to Salesforce using JWT')
    parser.add_argument('-c', '--configfile', required=True,
                                            help='path to configuration file')
    parser.add_argument('-i', '--instance', required=True,
                                            help='name of the instance to use from the config file')

    args = parser.parse_args()

    config = configparser.ConfigParser()
    config.read(args.configfile)
    client_id = config[args.instance]['client_id']
    username = config[args.instance]['username']
    loginURL = config[args.instance]['loginURL']
    keyfile = config[args.instance]['keyfile']
    authURL = config[args.instance]['authURL']

    res = auth(client_id, username, loginURL, keyfile, authURL)
    pp = pprint.PrettyPrinter(width=80, compact=False)
    pp.pprint(res)
    

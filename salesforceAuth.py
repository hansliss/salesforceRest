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

def auth(configfile, instance):

    config = configparser.ConfigParser()
    config.read(configfile)
    session_cache = config[instance]['session_cache']
    api_version = config[instance]['api_version']
    try:
        with open(session_cache, "r") as f:
            res = json.loads(f.read())
            url = res["instance_url"] + "/services/data/" + api_version + "/limits"
            headers = {
       	        "Authorization": res["token_type"] + " " + res["access_token"]
            }
            result = requests.get(url, headers=headers)
            if result.status_code == 200:
                return res
            else:
                print("Reauthorizing")
                res = None
    except:
        print("Failed to load cached session data")

    client_id = config[instance]['client_id']
    username = config[instance]['username']
    loginURL = config[instance]['loginURL']
    keyfile = config[instance]['keyfile']
    authURL = config[instance]['authURL']


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
        print("Error: " + str(result.status_code) + " : " + result.reason)
        return None
    else:
        authInfo=json.loads(result.text)
        with open(session_cache, "w") as f:
            f.write(result.text)
        return authInfo

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Authenticate to Salesforce using JWT')
    parser.add_argument('-c', '--configfile', required=True,
                                            help='path to configuration file')
    parser.add_argument('-i', '--instance', required=True,
                                            help='name of the instance to use from the config file')

    res = auth(args.configfile, args.instance)
    pp = pprint.PrettyPrinter(width=80, compact=False)
    pp.pprint(res)
    

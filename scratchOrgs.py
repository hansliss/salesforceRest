#!/usr/lib/python

"""auth.py: Get scratch org status."""

__author__ = "Hans Liss"
__copyright__ = "Copyright 2022, Hans Liss"
__license__ = "BSD 2-Clause License"
__version__ = "1.0"
__maintainer__ = "Hans Liss"
__email__ = "Hans@Liss.nu"
__status__ = "Example code"

import salesforceAuth
import requests
import pprint
import json
import configparser
import argparse



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Authenticate to Salesforce using JWT')
    parser.add_argument('-c', '--configfile', required=True,
                        help='path to configuration file')
    parser.add_argument('-i', '--instance', required=True,
                        help='name of the instance to use from the config file')
    
    args = parser.parse_args()
    
    config = configparser.ConfigParser()
    config.read(args.configfile)
    api_version = config[args.instance]['api_version']
    
    res = salesforceAuth.auth(args.configfile, args.instance)
    if res != None:
        url = res["instance_url"] + "/services/data/" + api_version + "/limits"
        headers = {
       	    "Authorization": res["token_type"] + " " + res["access_token"]
        }
        result = requests.get(url, headers=headers)
        if result.status_code != 200:
            print("Error: " + str(result.status_code) + " : " + result.reason)
        else:
            limits=json.loads(result.text)
            print("Active scratch orgs remaining: " + str(limits["ActiveScratchOrgs"]["Remaining"]) + " (max " + str(limits["ActiveScratchOrgs"]["Max"]) + ")")
            print("Daily scratch orgs remaining: " + str(limits["DailyScratchOrgs"]["Remaining"]) + " (max " + str(limits["DailyScratchOrgs"]["Max"]) + ")")

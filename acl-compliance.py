"""
Check the ACL on your devices are compliant
Goal: catching missing and unexpected entries
"""

import json
from operator import invert
from rich import print
from ipfabric import IPFClient
from deepdiff import DeepDiff as ddiff
from jsondiff import diff
from modules.acl_functions import fetch_acl

import os
import sys
from rich import print
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.realpath(os.path.dirname(sys.argv[0])),'102.env'), override=True)
#load_dotenv(os.path.join(os.path.realpath(os.path.dirname(sys.argv[0])),'103.env'), override=True)

#DEVICES_LIST = ["L66EXR1", "L66R4", "L66R3", "L38R7", "L38R8"]

def ignore_order_func(level):
    return "action" not in level.path()

with open("compliance.json", "r") as compliance_file:
    compliance_json = json.load(compliance_file)

acl_name = os.getenv("ACL_NAME", "")
snapshot_id = os.getenv("SNAPSHOT_ID", "$last")
ipf = IPFClient(snapshot_id=snapshot_id)
#acl_ipf = fetch_acl(ipf, DEVICES_LIST[0], "SSH")
#diff(compliance_json, acl_ipf["ACL_SSH"])
#ddiff(compliance_json, acl_ipf["ACL_SSH"])
for device in ipf.inventory.devices.all(columns=["hostname"]):
    print(f'\n{device["hostname"]}')
    acl_ipf = fetch_acl(ipf, device["hostname"], acl_name)
    if acl_ipf == {}:
        print(f"ACL '{acl_name}' not configured")
    for _ in acl_ipf.keys():
        acl_diff = ddiff(compliance_json, acl_ipf[acl_name], ignore_order=True, ignore_order_func=ignore_order_func)
        #print(ddiff(compliance_json, acl_ipf[acl_name], ignore_order=True, ignore_order_func=ignore_order_func))
        if acl_ipf != {}:
            print(acl_diff)
        else:
            print(f"ACL '{acl_name}' correctly configured")
"""
Check the ACL on your devices are compliant
Goal: catching missing and unexpected entries
"""

import json
from operator import invert
from queue import Empty
from rich import print
from ipfabric import IPFClient
from deepdiff import DeepDiff as ddiff
from jsondiff import diff
from modules.acl_functions import fetch_acl

import os
import sys
from rich import print_json
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

for device in ipf.inventory.devices.all(columns=["hostname"]):
    print(f'\n{device["hostname"]} - ', end="")
    acl_ipf = fetch_acl(ipf, device["hostname"], acl_name)
    if acl_ipf == {}:
        print(f"\U0000274c - ACL '{acl_name}' not configured")
    for _ in acl_ipf.keys():
        if acl_diff := ddiff(compliance_json, acl_ipf[acl_name], ignore_order=True, ignore_order_func=ignore_order_func):
            print(f"\U00002757 - ACL exists but is different\n{acl_diff}")
            #print_json(acl_diff.to_json())
        else:
            print(f"\U00002705 - ACL '{acl_name}' correctly configured")
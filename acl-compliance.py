"""
Check the ACL on your devices are compliant
Goal: catching missing and unexpected entries
"""

import json
from rich import print
from ipfabric import IPFClient
from deepdiff import DeepDiff as ddiff
from jsondiff import diff
from modules.acl_functions import fetch_acl
DEVICES_LIST = ["L66EXR1", "L66R4"]

def ignore_order_func(level):
    return "action" not in level.path()

with open("compliance.json", "r") as compliance_file:
    compliance_json = json.load(compliance_file)

api_token = "07f1a49aebddac3a5161d5f5384dec00"
url = "https://jupee.ipf.cx/"
ipf = IPFClient(base_url=url, token = api_token, snapshot_id="12dd8c61-129c-431a-b98b-4c9211571f89")
#acl_ipf = fetch_acl(ipf, DEVICES_LIST[0], "SSH")
#diff(compliance_json, acl_ipf["ACL_SSH"])
#ddiff(compliance_json, acl_ipf["ACL_SSH"])
for device in DEVICES_LIST:
    acl_ipf = fetch_acl(ipf, device, "SSH")
    for acl in acl_ipf.keys():
        print(ddiff(compliance_json, acl_ipf["ACL_SSH"], ignore_order=True, ignore_order_func=ignore_order_func))
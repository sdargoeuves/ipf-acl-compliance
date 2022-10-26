"""
Functions to deal with ACL
"""
from ipfabric import IPFClient

def fetch_acl(ipf: IPFClient, device: str, acl_filter: str):
    """
    Return all ACLs matching device and the acl filter
    """
    all_acl = {}
    dev_acl_filter = {
        "hostname": ["like", device],
        "policyName": ["like", acl_filter],
    }
    raw_acls = ipf.fetch_all(url="tables/security/acl", filters=dev_acl_filter)
    unique_acls = list({acl["policyName"] for acl in raw_acls})
    for acl_name in unique_acls:
        for acl in raw_acls:
            if acl["policyName"] == acl_name:
                if acl_name in all_acl:
                    all_acl[acl_name].append({"action": acl["action"], "ipProtocol": acl["ipProtocol"], "ipSrc": acl["ipSrc"], "ipDst": acl["ipDst"], "dstPorts": acl["dstPorts"]})
                else:
                    all_acl[acl_name] = [{"action": acl["action"], "ipProtocol": acl["ipProtocol"], "ipSrc": acl["ipSrc"], "ipDst": acl["ipDst"], "dstPorts": acl["dstPorts"]}]

    return all_acl

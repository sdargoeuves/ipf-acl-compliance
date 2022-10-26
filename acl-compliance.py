"""
Check the ACL on your devices are compliant
Goal: catching missing and unexpected entries
"""

import json
import os
import sys
from pathlib import Path

import typer
from deepdiff import DeepDiff
from dotenv import load_dotenv
from ipfabric import IPFClient
from rich import print
from rich.table import Table

from modules.acl_functions import fetch_acl

try:
    from yaspin import yaspin
    YASPIN_ANIMATION = True
except ImportError:
    YASPIN_ANIMATION = False

# Get Current Path
CURRENT_PATH = Path(os.path.realpath(os.path.dirname(sys.argv[0]))).resolve()
# Load environment variables
load_dotenv(os.path.join(CURRENT_PATH, ".env"), override=True)

app = typer.Typer(add_completion=False)


@app.command()
def main(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose mode."),
    table_mode: bool = typer.Option(False, "--table", "-t", help="Enable table mode."),
):
    """
    Script to check ACL compliance
    """
    # Fonction to ignore the order inside the ACL -> ok if using implicit deny!!
    def ignore_order_func(level):
        return "action" not in level.path()

    # Create variables
    acl_name = os.getenv("ACL_NAME", "")
    snapshot_id = os.getenv("SNAPSHOT_ID", "$last")
    acl_reference_file = os.getenv("ACL_REFERENCE_FILE", "compliance.json")
    device_filter = os.getenv("DEVICE_FILTER")
    acl_not_present = "\U0000274c"  # red cross
    acl_not_compliant = "\U00002757"  # exclamation
    acl_compliant = "\U00002705"  # green check

    ipf = IPFClient(snapshot_id=snapshot_id, verbose=False)

    if table_mode:
        output_table = Table(title="ACL Compliance check")
        output_table.add_column("Device", style="cyan", no_wrap=True)
        output_table.add_column("ACL status")
        output_table.add_column("Description")
        if YASPIN_ANIMATION:
            spinner = yaspin(
                text="Collecting ACL Data from IP Fabric",
                color="yellow",
                timer=True,
            )
            spinner.start()
        else:
            print("Collecting ACL Data from IP Fabric...")
    # Open the reference to check the ACL against
    with open(acl_reference_file, "r") as compliance_file:
        compliance_json = json.load(compliance_file)

    for device in ipf.inventory.devices.all(
        columns=["hostname"], filters=device_filter
    ):
        # print(f'{device["hostname"]} - ', end="")
        acl_ipf = fetch_acl(ipf, device["hostname"], acl_name)
        if not acl_ipf:
            acl_status = acl_not_present
            acl_comment = f"ACL '{acl_name}' not configured"
        for _ in acl_ipf.keys():
            if acl_diff := DeepDiff(
                compliance_json,
                acl_ipf[acl_name],
                ignore_order=True,
                ignore_order_func=ignore_order_func,
            ):
                acl_status = acl_not_compliant
                acl_comment = f"ACL '{acl_name}' exists but is not compliant"
                if verbose:
                    acl_comment += f"\n{acl_diff}"
            else:
                acl_status = acl_compliant
                acl_comment = f"ACL '{acl_name}' is correctly configured"
        if table_mode:
            output_table.add_row(device["hostname"], acl_status, acl_comment)
        else:
            print(f'{device["hostname"]} - {acl_status} - {acl_comment}')
    if table_mode:
        if YASPIN_ANIMATION:
            spinner.ok("✅ ")
        print(output_table)


if __name__ == "__main__":
    app()

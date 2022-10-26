"""
Check the ACL on your devices are compliant
Goal: catching missing and unexpected entries
"""

import os
import sys
import contextlib
import json
import typer
from loguru import logger
from rich import print
from rich.table import Table
from pathlib import Path
from ipfabric import IPFClient
from dotenv import load_dotenv
from deepdiff import DeepDiff
from modules.acl_functions import fetch_acl

#with contextlib.suppress(ImportError):
#    from rich import print, table
try:
    from yaspin import yaspin

    YASPIN_ANIMATION = True
except ImportError:
    YASPIN_ANIMATION = False

# Get Current Path
CURRENT_PATH = Path(os.path.realpath(os.path.dirname(sys.argv[0]))).resolve()
# Load environment variables
load_dotenv(os.path.join(CURRENT_PATH, "102.env"), override=True)
# load_dotenv(os.path.join(CURRENT_PATH,'103.env'), override=True)

# LOG INFO
LOG_FILE = CURRENT_PATH / f'logs/{os.getenv("LOG_FILE","acl-compliance.log")}'
LOGGER_DEBUG_FORMAT = "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> |\
 <yellow><italic>{elapsed}</italic></yellow> |\
 <level>{level: <8}</level> | <level>{message}</level>"
LOGGER_INFO_FORMAT = "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> |\
 <yellow><italic>{elapsed}</italic></yellow> | <level>{message}</level>"
# Output info
ACL_NOT_PRESENT = os.getenv("ACL_NOT_PRESENT", "\U0000274c")  # red cross
ACL_NOT_COMPLIANT = os.getenv("ACL_NOT_COMPLIANT", "\U00002757")  # exclamation
ACL_COMPLIANT = os.getenv("ACL_COMPLIANT", "\U00002705")  # green check

app = typer.Typer(add_completion=False)


@app.command()
def main(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose mode."),
    table_mode: bool = typer.Option(False, "--table", "-t", help="Enable table mode."),
):
    """
    Script to check ACL compliance
    """
    # Initiate logger
    logger.remove()
    if verbose:
        logger.add(
            sys.stderr,
            colorize=True,
            level="DEBUG",
            format=LOGGER_DEBUG_FORMAT,
            diagnose=True,
        )
        logger.add(
            LOG_FILE,
            colorize=True,
            level="DEBUG",
            format=LOGGER_DEBUG_FORMAT,
            diagnose=True,
            rotation="500 KB",
            compression="bz2",
            retention="2 months",
        )
    else:
        # PRD mode, we don't show diagnose to avoid leaking info to the logs.
        logger.add(
            sys.stderr,
            colorize=True,
            level="INFO",
            format=LOGGER_INFO_FORMAT,
            diagnose=False,
        )
        logger.add(
            LOG_FILE,
            colorize=True,
            level="INFO",
            format=LOGGER_DEBUG_FORMAT,
            diagnose=False,
            rotation="500 KB",
            compression="bz2",
            retention="2 months",
        )

    # Fonction to ignore the order inside the ACL -> ok if using implicit deny!!
    def ignore_order_func(level):
        return "action" not in level.path()

    # Get variables from .env
    acl_name = os.getenv("ACL_NAME", "")
    snapshot_id = os.getenv("SNAPSHOT_ID", "$last")
    ipf = IPFClient(snapshot_id=snapshot_id, verbose=False)
    acl_reference_file = os.getenv("ACL_REFERENCE_FILE", "compliance.json")
    device_filter = os.getenv("DEVICE_FILTER")

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
    # Open the reference to check the ACL against
    with open(acl_reference_file, "r") as compliance_file:
        compliance_json = json.load(compliance_file)

    for device in ipf.inventory.devices.all(
        columns=["hostname"], filters=device_filter
    ):
        # print(f'{device["hostname"]} - ', end="")
        acl_ipf = fetch_acl(ipf, device["hostname"], acl_name)
        if acl_ipf == {}:
            acl_status = ACL_NOT_PRESENT
            acl_comment = f"ACL '{acl_name}' not configured"
            # print(f"\U0000274c - ACL '{acl_name}' not configured")
        for _ in acl_ipf.keys():
            if acl_diff := DeepDiff(
                compliance_json,
                acl_ipf[acl_name],
                ignore_order=True,
                ignore_order_func=ignore_order_func,
            ):
                acl_status = ACL_NOT_COMPLIANT
                acl_comment = f"ACL '{acl_name}' exists but is not compliant"
                # print("\U00002757 - ACL exists but is not compliant")
                if verbose:
                    acl_comment += f"\n{acl_diff}"
            else:
                acl_status = ACL_COMPLIANT
                acl_comment = f"ACL '{acl_name}' is correctly configured"
                # print(f"\U00002705 - ACL '{acl_name}' correctly configured")
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

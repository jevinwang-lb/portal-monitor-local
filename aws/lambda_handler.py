"""AWS Lambda entry point for app/monitor.py.

monitor.py reads domains.txt and reads/writes status.json on the
local filesystem. Lambda has no durable disk, so this handler
proxies both through S3:

    S3 -> /tmp -> monitor.main() -> /tmp -> S3

monitor.py itself is unchanged and stays unaware of Lambda.
"""

import os
import sys

import boto3
from botocore.exceptions import ClientError


# ============================================================
# Configuration
# ============================================================

STATE_BUCKET = os.environ["STATE_BUCKET"]

STATE_KEY = os.environ.get(
    "STATE_KEY",
    "portal-monitor/status.json",
)

DOMAINS_KEY = os.environ.get(
    "DOMAINS_KEY",
    "portal-monitor/domains.txt",
)

LOCAL_STATE = "/tmp/status.json"

LOCAL_DOMAINS = "/tmp/domains.txt"


# monitor.py resolves these at import time, so they have to be
# set before it is imported inside the handler.
os.environ["STATE_FILE"] = LOCAL_STATE
os.environ["DOMAINS_FILE"] = LOCAL_DOMAINS


s3 = boto3.client("s3")


# ============================================================
# S3
# ============================================================

def download(key, path):

    try:

        s3.download_file(
            STATE_BUCKET,
            key,
            path,
        )

        return True

    except ClientError as e:

        if e.response["Error"]["Code"] in [
            "404",
            "NoSuchKey",
        ]:

            return False

        raise


def upload(path, key):

    s3.upload_file(
        path,
        STATE_BUCKET,
        key,
    )


# ============================================================
# Entry point
# ============================================================

def handler(event, context):

    print(
        "State bucket:",
        STATE_BUCKET,
    )

    # --------------------------------------------------------
    # domains.txt is required. Without it monitor.py would exit
    # 2 with a confusing "file not found" on a /tmp path.
    # --------------------------------------------------------

    if not download(
        DOMAINS_KEY,
        LOCAL_DOMAINS,
    ):

        raise RuntimeError(
            f"domains file not found: "
            f"s3://{STATE_BUCKET}/{DOMAINS_KEY}"
        )

    # --------------------------------------------------------
    # Missing state is a legitimate first run. Clear any file
    # left in /tmp by an earlier invocation on the same warm
    # container, otherwise that stale state would be treated
    # as authoritative.
    # --------------------------------------------------------

    had_state = download(
        STATE_KEY,
        LOCAL_STATE,
    )

    if not had_state and os.path.exists(LOCAL_STATE):

        os.remove(LOCAL_STATE)

    print(
        "Previous state loaded:",
        had_state,
    )

    # --------------------------------------------------------
    # monitor.main() always ends in sys.exit().
    # --------------------------------------------------------

    import monitor

    try:

        monitor.main()

        exit_code = 0

    except SystemExit as e:

        exit_code = e.code or 0

    # --------------------------------------------------------
    # A fatal config error exits before writing state, so only
    # push back a file monitor actually produced.
    # --------------------------------------------------------

    if os.path.exists(LOCAL_STATE):

        upload(
            LOCAL_STATE,
            STATE_KEY,
        )

        print(
            "State saved:",
            f"s3://{STATE_BUCKET}/{STATE_KEY}",
        )

    if exit_code != 0:

        raise RuntimeError(
            f"monitor exited with {exit_code}"
        )

    return {"status": "ok"}

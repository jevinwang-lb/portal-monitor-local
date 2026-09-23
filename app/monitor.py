import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone


# ============================================================
# Configuration
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

# ------------------------------------------------------------
# Files
# ------------------------------------------------------------

DOMAINS_FILE = os.environ.get(
    "DOMAINS_FILE",
    os.path.join(BASE_DIR, "domains.txt"),
)

STATE_FILE = os.environ.get(
    "STATE_FILE",
    os.path.join(BASE_DIR, "status.json"),
)


# ------------------------------------------------------------
# Google Web Risk Lookup API
# ------------------------------------------------------------

LOOKUP_BASE_URL = (
    "https://webrisk.googleapis.com/v1/uris:search"
)

WEBRISK_API_KEY = os.environ.get(
    "WEBRISK_API_KEY"
)

# Matches the threat types the Transparency Report POC had
# already been validated against.
THREAT_TYPES = [
    value.strip()
    for value in os.environ.get(
        "THREAT_TYPES",
        "MALWARE,"
        "SOCIAL_ENGINEERING,"
        "UNWANTED_SOFTWARE",
    ).split(",")
    if value.strip()
]


# ------------------------------------------------------------
# Lookup HTTPS verification
#
# Normal / Kubernetes:
#   true
#
# Local behind Zero Trust TLS inspection:
#   export LOOKUP_VERIFY_TLS=false
# ------------------------------------------------------------

LOOKUP_VERIFY_TLS = (
    os.environ.get(
        "LOOKUP_VERIFY_TLS",
        "true",
    ).lower()
    == "true"
)


# ------------------------------------------------------------
# Teams / Power Automate Webhook
# ------------------------------------------------------------

ALERT_WEBHOOK_URL = os.environ.get(
    "ALERT_WEBHOOK_URL"
)

# Normal default:
#   true
#
# Local Zero Trust testing:
#   export WEBHOOK_VERIFY_TLS=false
#
# Kubernetes:
#   leave unset / true
WEBHOOK_VERIFY_TLS = (
    os.environ.get(
        "WEBHOOK_VERIFY_TLS",
        "true",
    ).lower()
    == "true"
)


# Test Job should fail the pipeline on CHECK_ERROR / webhook errors.
# Production CronJob leaves this unset / false so a flaky check
# does not mark the CronJob failed.
FAIL_ON_ERROR = (
    os.environ.get(
        "FAIL_ON_ERROR",
        "false",
    ).lower()
    == "true"
)


# ------------------------------------------------------------
# Timeouts
# ------------------------------------------------------------

HTTP_TIMEOUT_SECONDS = int(
    os.environ.get(
        "HTTP_TIMEOUT_SECONDS",
        "15",
    )
)

MAX_RETRIES = int(
    os.environ.get(
        "MAX_RETRIES",
        "3",
    )
)

RETRY_DELAY_SECONDS = int(
    os.environ.get(
        "RETRY_DELAY_SECONDS",
        "2",
    )
)


# ============================================================
# Helpers
# ============================================================

def now_iso():

    return datetime.now(
        timezone.utc
    ).isoformat()


class FatalLookupError(Exception):
    """API key rejected or Web Risk API not enabled.

    Retrying will not help and every remaining domain would
    fail the same way, so abort the whole run instead.
    """


def open_url(request, verify_tls):

    if verify_tls:

        return urllib.request.urlopen(
            request,
            timeout=HTTP_TIMEOUT_SECONDS,
        )

    print(
        "WARNING: TLS verification "
        "is disabled"
    )

    return urllib.request.urlopen(
        request,
        timeout=HTTP_TIMEOUT_SECONDS,
        context=ssl._create_unverified_context(),
    )


# ============================================================
# Domains
# ============================================================

def load_domains():

    if not os.path.exists(
        DOMAINS_FILE
    ):

        print(
            "ERROR: domains file not found:"
        )

        print(
            DOMAINS_FILE
        )

        sys.exit(2)

    domains = []

    with open(
        DOMAINS_FILE,
        "r",
        encoding="utf-8",
    ) as f:

        for line in f:

            line = line.strip()

            if not line:
                continue

            if line.startswith("#"):
                continue

            domains.append(
                line
            )

    # Remove duplicates
    domains = list(
        dict.fromkeys(
            domains
        )
    )

    return domains


# ============================================================
# State
# ============================================================

def load_state():

    if not os.path.exists(
        STATE_FILE
    ):

        return {}

    try:

        with open(
            STATE_FILE,
            "r",
            encoding="utf-8",
        ) as f:

            return json.load(
                f
            )

    except Exception as e:

        print(
            "WARNING: failed to load state:"
        )

        print(
            e
        )

        return {}


def save_state(state):

    state_dir = os.path.dirname(
        STATE_FILE
    )

    if state_dir:

        os.makedirs(
            state_dir,
            exist_ok=True,
        )

    temp_file = (
        STATE_FILE + ".tmp"
    )

    with open(
        temp_file,
        "w",
        encoding="utf-8",
    ) as f:

        json.dump(
            state,
            f,
            indent=2,
            ensure_ascii=False,
        )

    os.replace(
        temp_file,
        STATE_FILE,
    )


# ============================================================
# Web Risk URL
# ============================================================

# Web Risk requires a valid URI. domains.txt historically holds
# bare hosts and host/path entries, so supply a scheme when the
# entry does not carry one.
def build_target_uri(domain):

    if "://" in domain:

        return domain

    return "https://" + domain


def build_lookup_url(domain):

    params = [
        ("uri", build_target_uri(domain)),
        ("key", WEBRISK_API_KEY),
    ]

    for threat_type in THREAT_TYPES:

        params.append(
            ("threatTypes", threat_type)
        )

    return (
        LOOKUP_BASE_URL
        + "?"
        + urllib.parse.urlencode(params)
    )


# ============================================================
# Single domain check
# ============================================================

# An empty JSON object means the URI is on none of the
# requested threat lists.
def parse_status(payload):

    threat_types = (
        payload
        .get("threat", {})
        .get("threatTypes", [])
    )

    if threat_types:

        print(
            "Threat types:",
            ", ".join(threat_types),
        )

        return "UNSAFE"

    return "SAFE"


def check_domain_once(domain):

    request = urllib.request.Request(
        build_lookup_url(domain),
        method="GET",
    )

    try:

        with open_url(
            request,
            LOOKUP_VERIFY_TLS,
        ) as response:

            body = response.read().decode(
                "utf-8"
            )

    except urllib.error.HTTPError as e:

        # Google puts the actual reason (SERVICE_DISABLED,
        # API_KEY_SERVICE_BLOCKED, ...) in the body, not the
        # status line. Never diagnose one of these blind.
        try:

            detail = e.read().decode(
                "utf-8",
                "replace",
            ).strip()

        except Exception:

            detail = ""

        if e.code in [
            400,
            401,
            403,
        ]:

            raise FatalLookupError(
                f"Web Risk rejected the request "
                f"(HTTP {e.code}). Check WEBRISK_API_KEY "
                f"and that the Web Risk API is enabled.\n"
                f"{detail}"
            )

        print(
            "Web Risk error body:",
            detail,
        )

        raise

    return parse_status(
        json.loads(body)
    )


# ============================================================
# Retry
# ============================================================

def check_domain(domain):

    for attempt in range(
        1,
        MAX_RETRIES + 1,
    ):

        print(
            f"Attempt "
            f"{attempt}/{MAX_RETRIES}"
        )

        try:

            return check_domain_once(
                domain
            )

        except FatalLookupError:

            raise

        except Exception as e:

            print(
                f"CHECK ERROR "
                f"(attempt {attempt}):"
            )

            print(
                e
            )

            if attempt < MAX_RETRIES:

                time.sleep(
                    RETRY_DELAY_SECONDS
                )

                continue

    return "CHECK_ERROR"


# ============================================================
# Teams / Power Automate Webhook
# ============================================================

def send_webhook(event):

    if not ALERT_WEBHOOK_URL:

        print(
            "INFO: ALERT_WEBHOOK_URL "
            "not configured"
        )

        return

    payload = json.dumps(
        event,
        ensure_ascii=False,
    ).encode(
        "utf-8"
    )

    request = urllib.request.Request(
        ALERT_WEBHOOK_URL,
        data=payload,
        headers={
            "Content-Type":
                "application/json",
        },
        method="POST",
    )

    with open_url(
        request,
        WEBHOOK_VERIFY_TLS,
    ) as response:

        print(
            "Webhook HTTP:",
            response.status,
        )


# ============================================================
# Checks
# ============================================================

def collect_statuses(domains):

    results = {}

    for domain in domains:

        print()

        print(
            "-" * 60
        )

        print(
            "Checking:",
            domain,
        )

        print(
            "Lookup URI:",
            build_target_uri(domain),
        )

        results[domain] = check_domain(
            domain
        )

    return results


# ============================================================
# Main
# ============================================================

def main():

    print(
        "=" * 60
    )

    print(
        "Portal Safe Browsing Monitor"
    )

    print(
        "Time:",
        now_iso(),
    )

    print(
        "Domains file:",
        DOMAINS_FILE,
    )

    print(
        "State file:",
        STATE_FILE,
    )

    print(
        "Threat types:",
        ", ".join(THREAT_TYPES),
    )

    print(
        "API key configured:",
        bool(WEBRISK_API_KEY),
    )

    print(
        "Lookup TLS verification:",
        LOOKUP_VERIFY_TLS,
    )

    print(
        "Webhook configured:",
        bool(ALERT_WEBHOOK_URL),
    )

    print(
        "Webhook TLS verification:",
        WEBHOOK_VERIFY_TLS,
    )

    print(
        "Fail on error:",
        FAIL_ON_ERROR,
    )

    print(
        "=" * 60
    )


    # --------------------------------------------------------
    # API key
    # --------------------------------------------------------

    if not WEBRISK_API_KEY:

        print(
            "ERROR: WEBRISK_API_KEY "
            "not configured"
        )

        sys.exit(2)

    if not THREAT_TYPES:

        print(
            "ERROR: THREAT_TYPES "
            "is empty"
        )

        sys.exit(2)


    # --------------------------------------------------------
    # Domains
    # --------------------------------------------------------

    domains = load_domains()

    if not domains:

        print(
            "ERROR: no domains configured"
        )

        sys.exit(2)

    print(
        f"Found {len(domains)} "
        "domain(s)"
    )


    # --------------------------------------------------------
    # State
    # --------------------------------------------------------

    old_state = load_state()

    new_state = {}

    notification_events = []

    monitor_errors = []

    webhook_failures = 0


    # --------------------------------------------------------
    # Web Risk
    # --------------------------------------------------------

    try:

        statuses = collect_statuses(
            domains
        )

    except FatalLookupError as e:

        print()

        print(
            "FATAL:",
            e,
        )

        sys.exit(2)

    for domain in domains:

        status = statuses.get(
            domain,
            "CHECK_ERROR",
        )


        # --------------------------------------------
        # Previous state
        # --------------------------------------------

        previous = old_state.get(
            domain
        )


        # --------------------------------------------
        # Output
        # --------------------------------------------

        print(
            "Previous:",
            (
                previous
                if previous is not None
                else "(first check)"
            ),
        )

        print(
            "Current :",
            status,
        )


        # ============================================
        # Display current status
        # ============================================

        if status == "UNSAFE":

            print()

            print(
                "🚨 UNSAFE:",
                domain,
            )

        elif status == "SAFE":

            print()

            print(
                "✅ SAFE:",
                domain,
            )

        else:

            print()

            print(
                "🔴 CHECK_ERROR:",
                domain,
            )


        # ============================================
        # CHECK_ERROR
        # ============================================

        if status == "CHECK_ERROR":

            monitor_errors.append(
                {
                    "event":
                        "monitor_error",
                    "domain":
                        domain,
                    "time":
                        now_iso(),
                }
            )

            # Preserve previous valid state
            if previous is not None:

                new_state[
                    domain
                ] = previous

            continue


        # ============================================
        # First valid SAFE / UNSAFE check
        # ============================================

        if previous is None:

            new_state[
                domain
            ] = status

            # First check is already UNSAFE
            if status == "UNSAFE":

                event = {
                    "event":
                        "status_changed",
                    "domain":
                        domain,
                    "previous":
                        None,
                    "current":
                        "UNSAFE",
                    "time":
                        now_iso(),
                }

                notification_events.append(
                    event
                )

                print(
                    "🚨 FIRST CHECK "
                    "AND UNSAFE"
                )

            else:

                print(
                    "First check: "
                    "no notification"
                )

            continue


        # ============================================
        # Save valid SAFE / UNSAFE state
        # ============================================

        new_state[
            domain
        ] = status


        # ============================================
        # No state change
        # ============================================

        if previous == status:

            print(
                "No status change."
            )

            continue


        # ============================================
        # SAFE <-> UNSAFE
        # ============================================

        event = {
            "event":
                "status_changed",
            "domain":
                domain,
            "previous":
                previous,
            "current":
                status,
            "time":
                now_iso(),
        }

        notification_events.append(
            event
        )

        print()

        print(
            "🔔 STATUS CHANGED:"
        )

        print(
            f"   {previous} "
            f"-> {status}"
        )




    # ========================================================
    # Save state
    # ========================================================

    save_state(
        new_state
    )

    print()

    print(
        "=" * 60
    )

    print(
        "State saved:",
        STATE_FILE,
    )


    # ========================================================
    # Notifications
    # ========================================================

    if notification_events:

        print()

        print(
            "Notification events:",
            len(
                notification_events
            ),
        )

        for event in (
            notification_events
        ):

            print(
                "Event:",
                json.dumps(
                    event,
                    ensure_ascii=False,
                ),
            )

            try:

                send_webhook(
                    event
                )

            except Exception as e:

                print(
                    "Webhook failed:",
                    e,
                )

                webhook_failures += 1

    else:

        print()

        print(
            "No notification events."
        )


    # ========================================================
    # Monitor errors
    # ========================================================

    if monitor_errors:

        print()

        print(
            "Monitor errors:",
            len(
                monitor_errors
            ),
        )

        for error in monitor_errors:

            print(
                json.dumps(
                    error,
                    ensure_ascii=False,
                )
            )


    print(
        "=" * 60
    )

    exit_code = 0

    if monitor_errors or webhook_failures:

        if FAIL_ON_ERROR:

            exit_code = 1

    sys.exit(
        exit_code
    )


# ============================================================
# Entry point
# ============================================================

if __name__ == "__main__":

    main()

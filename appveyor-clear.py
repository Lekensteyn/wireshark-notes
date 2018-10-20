#!/usr/bin/env python3
"""
Clears the build history, removing all but the last 100 builds. Usage:

Go to https://ci.appveyor.com/api-keys for an account-specific (v1) token. Then:

    export APPVEYOR_TOKEN=...
    ./appveyor-clear.py Lekensteyn/wireshark

Other options exist, use ./appveyor-clear.py --help to see them all.
"""

import argparse
import os
import sys
import requests

parser = argparse.ArgumentParser()
parser.add_argument("--token", default=os.environ.get("APPVEYOR_TOKEN"),
                    help="v1 API token (defaults to APPVEYOR_TOKEN environment variable). See "
                    "https://ci.appveyor.com/api-keys")
parser.add_argument("--max-builds", type=int, default=100,
                    help="Maximum number of recent builds to keep")
parser.add_argument("--dry-run", action="store_true",
                    help="Do not actually delete builds")
parser.add_argument("project",
                    help="Account name plus project slug (e.g. Lekensteyn/wireshark)")

base = "https://ci.appveyor.com/api"
history_url = "%s/projects/{project}/history?recordsNumber=1000" % base
build_url = "%s/builds/{buildId}" % base

args = parser.parse_args()
if not args.token:
    parser.error("Missing APPVEYOR_TOKEN environment variable")
if args.token.startswith("v2."):
    parser.error("Only a v1 token is supported")

headers = {
    "Authorization": "Bearer %s" % args.token,
}
# Retrieve builds for the project
r = requests.get(history_url.format(project=args.project), headers=headers)
r.raise_for_status()  # Does the project exist?
builds = r.json()["builds"]
count = len(builds)
builds = builds[args.max_builds:]
if not builds:
    print("Found %d builds, nothing to remove" % count)
else:
    print("About to remove %d builds" % len(builds))
    for build in builds:
        print("Removing %d %s" % (build["buildId"], build["message"]))
        if not args.dry_run:
            r = requests.delete(build_url.format(buildId=build["buildId"]),
                                headers=headers)
            r.raise_for_status()  # If this fails, perhaps token is invalid.

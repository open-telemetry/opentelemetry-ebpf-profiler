#!/usr/bin/env python3
"""Post or update the eBPF bloatcheck report comment on a pull request.

The report file is written by bloat-o-meter (see BLOATCHECK_REPORT). Comments
start with MARKER so that repeated runs update the existing comment.

Exits with an error unless GITHUB_TOKEN, REPO, BASE_COMMIT, HEAD_SHA,
HEAD_REPO, HEAD_BRANCH and RUN_URL are all set. The report artifact is
controlled by the pull request, so it is only posted after resolving the
open pull request for the run's head repository and branch, and verifying
that its head commit matches the run's head commit (HEAD_SHA).
"""

import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

MARKER = "<!-- ebpf-bloatcheck-report -->"
API_BASE = "https://api.github.com"
REQUIRED_ENV = ("GITHUB_TOKEN", "REPO", "BASE_COMMIT", "HEAD_SHA",
                "HEAD_REPO", "HEAD_BRANCH", "RUN_URL")

# The report artifact is controlled by the pull request: accept only the
# markdown table grammar bloat-o-meter emits, or the no-differences line.
# Legit table cells are symbol names and numbers, which cannot contain
# markdown or mention syntax; reject anything that could. The length is
# capped at GitHub's comment limit.
NO_DIFF_REPORT = "No eBPF size differences."
REPORT_ROW_RE = re.compile(r"\|([^|]*\|)+")
REPORT_MARKDOWN_RE = re.compile(r"[@`<>\[\]()!\\]")
MAX_REPORT_LEN = 65536


def api_request(method, path, token, payload=None):
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "User-Agent": "ebpf-profiler-bloatcheck",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    data = None
    if payload is not None:
        data = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(API_BASE + path, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = resp.read()
    return json.loads(body) if body else None


def find_comment_id(repo, pr_number, token):
    page = 1
    while True:
        comments = api_request(
            "GET", f"/repos/{repo}/issues/{pr_number}/comments?per_page=100&page={page}", token)
        if not comments:
            return None
        for comment in comments:
            if comment.get("body", "").startswith(MARKER):
                return comment["id"]
        page += 1


def find_pull(repo, head_repo, head_branch, head_sha, token):
    # Resolve the pull request from the run's head repository and branch;
    # the workflow_run event does not carry the pull request number.
    head = urllib.parse.quote(f"{head_repo}:{head_branch}", safe=":/")
    pulls = api_request("GET", f"/repos/{repo}/pulls?head={head}&state=open&per_page=100",
                        token) or []
    for pull in pulls:
        if pull.get("head", {}).get("sha") == head_sha:
            return pull
    return None


def main():
    missing = [name for name in REQUIRED_ENV if not os.environ.get(name)]
    if missing:
        print(f"Missing required environment variables: {', '.join(missing)}; doing nothing.",
              file=sys.stderr)
        return 1
    token = os.environ["GITHUB_TOKEN"]
    repo = os.environ["REPO"]
    base_commit = os.environ["BASE_COMMIT"]
    head_sha = os.environ["HEAD_SHA"]
    head_repo = os.environ["HEAD_REPO"]
    head_branch = os.environ["HEAD_BRANCH"]
    run_url = os.environ["RUN_URL"]
    report_path = os.environ.get("BLOATCHECK_REPORT", "bloatcheck.md")

    if not re.fullmatch(r"[0-9a-f]{40}", base_commit):
        print(f"Invalid base commit '{base_commit}' in the report metadata; doing nothing.",
              file=sys.stderr)
        return 1

    # The report artifact is controlled by the pull request that produced
    # it: post only on the open pull request for the run's head repository
    # and branch, with its head commit matching the run. A mismatch is the
    # normal outcome for a superseded run.
    pull = find_pull(repo, head_repo, head_branch, head_sha, token)
    if pull is None:
        print("No open pull request with this head commit; doing nothing.")
        return 0
    pr_number = pull["number"]

    try:
        with open(report_path) as f:
            report = f.read().strip()
    except OSError as e:
        print(f"No readable bloatcheck report ({e}), skipping the bloatcheck comment.")
        return 0
    if not report:
        print(f"Empty bloatcheck report in {report_path}, skipping the bloatcheck comment.")
        return 0
    if len(report) > MAX_REPORT_LEN or REPORT_MARKDOWN_RE.search(report) or (
            report != NO_DIFF_REPORT
            and not all(REPORT_ROW_RE.fullmatch(line) for line in report.split("\n"))):
        print(f"Bloatcheck report in {report_path} failed validation; doing nothing.",
              file=sys.stderr)
        return 1

    intro = (f"Rebuilt `support/ebpf/tracer.ebpf.*` blob sizes compared against "
             f"base commit `{base_commit}`.")
    footer = f"Updated automatically by the [CI-EBPF workflow]({run_url})."
    body = "\n".join([MARKER, "## eBPF tracer blob size report", "", intro, "", report, "",
                      f"<sub>{footer}</sub>", ""])

    try:
        comment_id = find_comment_id(repo, pr_number, token)
        if comment_id is None:
            api_request("POST", f"/repos/{repo}/issues/{pr_number}/comments", token,
                        {"body": body})
            print(f"Posted the bloatcheck report comment on pull request #{pr_number}.")
        else:
            api_request("PATCH", f"/repos/{repo}/issues/comments/{comment_id}", token,
                        {"body": body})
            print(f"Updated the bloatcheck report comment on pull request #{pr_number}.")
    except urllib.error.HTTPError as e:
        if e.code == 403:
            print("Insufficient permissions to post the bloatcheck comment (HTTP 403). "
                  "This is expected for pull requests from forks.")
            return 0
        print(f"Failed to post the bloatcheck comment: HTTP {e.code} {e.reason}: "
              f"{e.read().decode(errors='replace')}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

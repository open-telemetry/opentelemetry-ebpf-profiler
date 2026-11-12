#!/usr/bin/env python3
"""Post or update the eBPF bloatcheck report comment on a pull request.

The report file is written by bloat-o-meter (see BLOATCHECK_REPORT). Comments
start with MARKER so that repeated runs update the existing comment.

Exits with an error unless GITHUB_TOKEN, REPO, PR_NUMBER, BASE_COMMIT,
HEAD_SHA and RUN_URL are all set. The report artifact is controlled by the
pull request, so the pull request number is only posted after verifying
that the triggering run's head commit (HEAD_SHA) matches it.
"""

import json
import os
import sys
import urllib.error
import urllib.request

MARKER = "<!-- ebpf-bloatcheck-report -->"
API_BASE = "https://api.github.com"
REQUIRED_ENV = ("GITHUB_TOKEN", "REPO", "PR_NUMBER", "BASE_COMMIT", "HEAD_SHA", "RUN_URL")


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


def main():
    missing = [name for name in REQUIRED_ENV if not os.environ.get(name)]
    if missing:
        print(f"Missing required environment variables: {', '.join(missing)}; doing nothing.",
              file=sys.stderr)
        return 1
    token = os.environ["GITHUB_TOKEN"]
    repo = os.environ["REPO"]
    pr_number = os.environ["PR_NUMBER"]
    base_commit = os.environ["BASE_COMMIT"]
    head_sha = os.environ["HEAD_SHA"]
    run_url = os.environ["RUN_URL"]
    report_path = os.environ.get("BLOATCHECK_REPORT", "bloatcheck.md")

    # The report artifact is controlled by the pull request that produced it:
    # post only for its number, matching the run's head commit, while open.
    pull = api_request("GET", f"/repos/{repo}/pulls/{pr_number}", token)
    if pull.get("merge_commit_sha") != head_sha:
        print("Report artifact does not match the triggering run; doing nothing.",
              file=sys.stderr)
        return 1
    if pull.get("state") != "open":
        print(f"Pull request #{pr_number} is not open; doing nothing.")
        return 0

    try:
        with open(report_path) as f:
            report = f.read().strip()
    except OSError as e:
        print(f"No readable bloatcheck report ({e}), skipping the bloatcheck comment.")
        return 0
    if not report:
        print(f"Empty bloatcheck report in {report_path}, skipping the bloatcheck comment.")
        return 0

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

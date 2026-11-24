#!/usr/bin/env python3
"""Container-side client. No pipeline code, host paths or upstream keys."""
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request


def main():
    args = sys.argv[1:]
    # Compatibility for old conversation history; native Bash needs no wrapper.
    if args and args[0] == "shell":
        if "--" not in args:
            print("Use native Bash, or harbor-author shell -- <command>", file=sys.stderr)
            return 2
        command = args[args.index("--") + 1:]
        return subprocess.call(command) if command else 2
    endpoint = os.environ.get("HARBOR_AUTHOR_ENDPOINT", "")
    token = os.environ.get("HARBOR_AUTHOR_TOKEN", "")
    if not endpoint or not token:
        print("The author session is not connected to its host service", file=sys.stderr)
        return 1
    request = urllib.request.Request(
        endpoint + "/helper", data=json.dumps({"argv": args}).encode(),
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
    )
    # Do not let downloaded software's HTTP_PROXY redirect this capability.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=14400) as response:
            result = json.load(response)
        print(result.get("output", ""), end="", flush=True)
        return int(result.get("exit_code", 1))
    except urllib.error.HTTPError as exc:
        print(exc.read(4096).decode("utf-8", "replace"), file=sys.stderr)
    except (OSError, ValueError) as exc:
        print(f"Author service unavailable: {exc}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())

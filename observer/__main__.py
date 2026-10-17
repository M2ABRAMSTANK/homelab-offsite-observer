import argparse
import json
import os
from pathlib import Path
import sys

from . import config
from .runner import cycle
from .state import lock


def main(argv=None):
    parser = argparse.ArgumentParser(description="Outbound-only observer. Default: validate without network or writes.")
    parser.add_argument("--config", default="config.example.json")
    parser.add_argument("--live", action="store_true", help="Explicitly activate one cycle; requires enabled configuration.")
    parser.add_argument("--state-dir", default="/var/lib/offsite-observer")
    args = parser.parse_args(argv)
    try:
        cfg = config.load(args.config, secure=args.live)
        if not args.live:
            print(json.dumps({"schema": 1, "mode": "dry-run", "configuration_valid": True,
                              "network_requests": 0, "state_writes": 0, "configured_enabled": cfg["enabled"]}))
            return 0
        if os.geteuid() == 0:
            raise ValueError("live runtime must not be root")
        if not cfg["enabled"] or not cfg["provider"]["contract_verified"]:
            raise ValueError("live activation and provider contract acceptance required")
        directory = os.environ.get("CREDENTIALS_DIRECTORY", "")
        if not directory or Path(args.config).resolve() != (Path(directory) / "config").resolve():
            raise ValueError("live configuration must match the protected credential copy")
        credentials = {"provider_token": config.token(directory, "provider_token")}
        if cfg["private"]["enabled"]:
            credentials["private_token"] = config.token(directory, "private_token")
        with lock(args.state_dir):
            evidence = cycle(cfg, credentials, args.state_dir)
        print(json.dumps(evidence, separators=(",", ":"), allow_nan=False))
        return 0 if evidence["clock_trusted"] and evidence["provider_heartbeat"] else 2
    except BlockingIOError:
        print('{"schema":1,"error":"overlap_refused"}', file=sys.stderr)
        return 3
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        # Avoid exception messages, tracebacks, paths, URLs, and credential content in logs.
        print('{"schema":1,"error":"configuration_or_runtime_failure"}', file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

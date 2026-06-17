#!/usr/bin/env python3
import argparse
import json
import os
import sys
from dataclasses import dataclass
from typing import Any
from urllib import error, request


MALICIOUS_VALUES = {"bad", "high-risk", "known-bad", "malicious", "suspicious"}
BENIGN_VALUES = {"benign", "clean", "known-good", "not_malicious"}
UNKNOWN_VALUES = {"", "no_match", "none", "not_found", "unknown"}


@dataclass(frozen=True)
class AISConfig:
    base_url: str
    path: str = "/search"
    api_key: str | None = None
    auth_header: str = "Authorization"
    auth_scheme: str = "Bearer"
    timeout: int = 15

    @property
    def url(self) -> str:
        return f"{self.base_url.rstrip('/')}/{self.path.lstrip('/')}"


def load_config(env: dict[str, str] | None = None) -> AISConfig:
    env = env or os.environ
    base_url = env.get("CTI_AIS_BASE_URL")
    if not base_url:
        raise ValueError("CTI_AIS_BASE_URL is required")

    timeout = int(env.get("CTI_AIS_TIMEOUT", "15"))
    return AISConfig(
        base_url=base_url,
        path=env.get("CTI_AIS_PATH", "/search"),
        api_key=env.get("CTI_AIS_API_KEY"),
        auth_header=env.get("CTI_AIS_AUTH_HEADER", "Authorization"),
        auth_scheme=env.get("CTI_AIS_AUTH_SCHEME", "Bearer"),
        timeout=timeout,
    )


def build_payload(query: str, query_type: str) -> bytes:
    return json.dumps({"query": query, "query_type": query_type}).encode("utf-8")


def extract_verdict(response_data: dict[str, Any]) -> str:
    if isinstance(response_data.get("malicious"), bool):
        return "malicious" if response_data["malicious"] else "benign"

    for key in ("verdict", "classification", "status"):
        value = response_data.get(key)
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in MALICIOUS_VALUES:
                return "malicious"
            if normalized in BENIGN_VALUES:
                return "benign"
            if normalized in UNKNOWN_VALUES:
                return "unknown"

    return "unknown"


def query_ais(config: AISConfig, query: str, query_type: str) -> dict[str, Any]:
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    if config.api_key:
        if config.auth_header.lower() == "authorization":
            headers[config.auth_header] = f"{config.auth_scheme} {config.api_key}".strip()
        else:
            headers[config.auth_header] = config.api_key

    http_request = request.Request(
        config.url,
        data=build_payload(query, query_type),
        headers=headers,
        method="POST",
    )

    try:
        with request.urlopen(http_request, timeout=config.timeout) as response:
            body = response.read().decode("utf-8")
    except error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        if exc.code == 404:
            return {
                "phase": 1,
                "source": "AIS",
                "query": query,
                "query_type": query_type,
                "verdict": "unknown",
                "details": "No match found in AIS",
                "raw_response": body,
            }
        raise RuntimeError(f"AIS request failed with status {exc.code}: {body}") from exc
    except error.URLError as exc:
        raise RuntimeError(f"Unable to reach AIS endpoint: {exc.reason}") from exc

    parsed = json.loads(body) if body else {}
    return {
        "phase": 1,
        "source": "AIS",
        "query": query,
        "query_type": query_type,
        "verdict": extract_verdict(parsed),
        "raw_response": parsed,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Phase 1 CTI checker: query an AIS endpoint for an IOC or threat actor."
    )
    parser.add_argument("query", help="IOC or threat actor to look up")
    parser.add_argument(
        "--type",
        choices=("ioc", "threat-actor"),
        required=True,
        dest="query_type",
        help="Type of lookup to perform",
    )
    parser.add_argument(
        "--raw",
        action="store_true",
        help="Include the full upstream AIS response in the output",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        config = load_config()
        result = query_ais(config, args.query, args.query_type)
    except (RuntimeError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"phase": 1, "source": "AIS", "error": str(exc)}), file=sys.stderr)
        return 1

    if not args.raw:
        result.pop("raw_response", None)

    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

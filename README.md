# cti-checker

Phase 1 of `cti-checker` is a small Python CLI that queries a configured AIS
endpoint for either an IOC or a threat actor and reports a normalized verdict.

## Phase 1 scope

- Query a single AIS-backed endpoint
- Support IOC and threat-actor lookups
- Return one of `malicious`, `benign`, or `unknown`
- Avoid guessing when the upstream response is ambiguous

## Usage

Set the AIS connection details with environment variables:

```bash
export CTI_AIS_BASE_URL="https://example-ais.internal"
export CTI_AIS_API_KEY="your-token"
```

Then run:

```bash
python3 /home/runner/work/cti-checker/cti-checker/cti_checker.py --type ioc 8.8.8.8
python3 /home/runner/work/cti-checker/cti-checker/cti_checker.py --type threat-actor "APT29"
```

Optional environment variables:

- `CTI_AIS_PATH` (default: `/search`)
- `CTI_AIS_TIMEOUT` (default: `15`)
- `CTI_AIS_AUTH_HEADER` (default: `Authorization`)
- `CTI_AIS_AUTH_SCHEME` (default: `Bearer`)

The script sends a JSON payload in this form:

```json
{
  "query": "8.8.8.8",
  "query_type": "ioc"
}
```

and prints a normalized JSON result like:

```json
{
  "phase": 1,
  "source": "AIS",
  "query": "8.8.8.8",
  "query_type": "ioc",
  "verdict": "unknown"
}
```
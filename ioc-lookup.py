#!/usr/bin/env python3
import argparse
import asyncio
import aiohttp
import json
import os
import time
from typing import Dict, Any

# ----------------------------
# CONFIG
# ----------------------------
VT_API_KEY = os.getenv("VT_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")
ABUSE_API_KEY = os.getenv("ABUSE_API_KEY")

TIMEOUT = 5

ALLOWLIST = {"8.8.8.8", "1.1.1.1", "google.com"}

# ----------------------------
# IOC TYPE DETECTION
# ----------------------------
def detect_type(ioc: str) -> str:
    if all(c.isdigit() or c == "." for c in ioc):
        return "ip"
    if len(ioc) == 64:
        return "hash"
    if "/" in ioc:
        return "url"
    return "domain"

# ----------------------------
# API CALLS
# ----------------------------
async def query_virustotal(session, ioc, ioc_type):
    url_map = {
        "ip": f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}",
        "domain": f"https://www.virustotal.com/api/v3/domains/{ioc}",
        "url": f"https://www.virustotal.com/api/v3/urls/{ioc}",
        "hash": f"https://www.virustotal.com/api/v3/files/{ioc}",
    }

    headers = {"x-apikey": VT_API_KEY}

    try:
        async with session.get(url_map[ioc_type], headers=headers, timeout=TIMEOUT) as resp:
            data = await resp.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)

            return {
                "source": "virustotal",
                "malicious": malicious,
                "score": malicious,
            }
    except Exception:
        return {"source": "virustotal", "malicious": 0, "score": 0}


async def query_alienvault(session, ioc):
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ioc}/general"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}

    try:
        async with session.get(url, headers=headers, timeout=TIMEOUT) as resp:
            data = await resp.json()
            pulses = len(data.get("pulse_info", {}).get("pulses", []))

            return {
                "source": "alienvault",
                "pulses": pulses,
                "score": pulses,
            }
    except Exception:
        return {"source": "alienvault", "pulses": 0, "score": 0}


async def query_abuseipdb(session, ioc):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSE_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ioc, "maxAgeInDays": 90}

    try:
        async with session.get(url, headers=headers, params=params, timeout=TIMEOUT) as resp:
            data = await resp.json()
            score = data.get("data", {}).get("abuseConfidenceScore", 0)

            return {
                "source": "abuseipdb",
                "abuse_score": score,
                "score": score,
            }
    except Exception:
        return {"source": "abuseipdb", "abuse_score": 0, "score": 0}


# ----------------------------
# SCORING
# ----------------------------
def calculate_score(results):
    total = 0
    reasons = []

    for r in results:
        if r["source"] == "virustotal" and r["malicious"] > 10:
            total += 40
            reasons.append("VirusTotal high detections")

        if r["source"] == "alienvault" and r["pulses"] > 0:
            total += 25
            reasons.append("AlienVault pulse hit")

        if r["source"] == "abuseipdb" and r["abuse_score"] > 50:
            total += 20
            reasons.append("High AbuseIPDB score")

    return total, reasons


def classify(score):
    if score >= 70:
        return "Malicious"
    elif score >= 40:
        return "Suspicious"
    return "Benign"


# ----------------------------
# EARLY EXIT
# ----------------------------
def early_exit(results):
    for r in results:
        if r["source"] == "virustotal" and r["malicious"] > 20:
            return True, "High VirusTotal detections"

        if r["source"] == "abuseipdb" and r["abuse_score"] > 90:
            return True, "Very high AbuseIPDB score"

    return False, ""


# ----------------------------
# MAIN ANALYSIS
# ----------------------------
async def analyze(ioc: str):
    start = time.time()

    if ioc in ALLOWLIST:
        return {
            "ioc": ioc,
            "verdict": "Benign",
            "score": 0,
            "reason": "Allowlisted",
            "time_taken": 0,
        }

    ioc_type = detect_type(ioc)

    async with aiohttp.ClientSession() as session:
        tasks = [
            query_virustotal(session, ioc, ioc_type),
        ]

        if ioc_type == "ip":
            tasks.append(query_abuseipdb(session, ioc))
            tasks.append(query_alienvault(session, ioc))

        results = await asyncio.gather(*tasks)

    # Early exit
    exit_flag, reason = early_exit(results)
    if exit_flag:
        return {
            "ioc": ioc,
            "type": ioc_type,
            "verdict": "Malicious",
            "score": 90,
            "reason": reason,
            "sources": results,
            "time_taken": round(time.time() - start, 2),
        }

    score, reasons = calculate_score(results)
    verdict = classify(score)

    return {
        "ioc": ioc,
        "type": ioc_type,
        "verdict": verdict,
        "score": score,
        "reasons": reasons,
        "sources": results,
        "time_taken": round(time.time() - start, 2),
    }


# ----------------------------
# CLI
# ----------------------------
def main():
    parser = argparse.ArgumentParser(description="Phase 2 IOC checker (API-based)")
    parser.add_argument("ioc", help="IOC to analyze")

    args = parser.parse_args()

    result = asyncio.run(analyze(args.ioc))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

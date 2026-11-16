#!/usr/bin/env python3
"""
Static Security Gate Scanner for global-letters (Task 11 --strict-missing)
NOTE: Static string/AST pattern checks alone do NOT guarantee runtime security.
Runtime behavior must be verified separately via the isolated integration test suite.
"""
import os
import re
import sys
import json

REQUIRED_FILES = [
    "src/lib/securityControls.ts",
    "src/app/api/verify-payment/route.ts",
    "src/app/api/webhook/paypal/route.ts",
    "firestore.rules",
    "src/app/api/cleanup/route.ts",
    "src/app/api/setup-assistant/route.ts",
    "src/app/api/setup-master/route.ts",
    "src/app/api/upload-knowledge/route.ts",
    "src/app/api/generate-letter/route.ts",
    "src/lib/gates/index.ts",
]

FORBIDDEN_PATTERNS = [
    (
        "src/app/api/verify-payment/route.ts",
        r"Returning mock verification success|return\s+NextResponse\.json\(\{\s*success:\s*true,\s*verified:\s*true\s*\}\)",
        "P0_PAYPAL_FAIL_OPEN",
    ),
    (
        "src/app/api/webhook/paypal/route.ts",
        r"raw_payload\s*:",
        "P0_WEBHOOK_RAW_PAYLOAD_PII_STORAGE",
    ),
    (
        "firestore.rules",
        r"allow\s+read,\s*write:\s*if\s+true",
        "P0_FIRESTORE_OPEN_RULES",
    ),
    (
        "src/app/api/cleanup/route.ts",
        r"unlinkSync|rmdirSync",
        "P1_DESTRUCTIVE_GET_CLEANUP",
    ),
    (
        "src/app/api/upload-knowledge/route.ts",
        r"Mock knowledge saved successfully",
        "P1_UPLOAD_KNOWLEDGE_MOCK_SUCCESS",
    ),
    (
        "src/app/api/generate-letter/route.ts",
        r"RATE_LIMIT_MAX\s*=\s*99999",
        "P1_UNBOUNDED_RATE_LIMIT",
    ),
]


def main():
    strict_missing = "--strict-missing" in sys.argv
    root = os.getcwd()
    findings = []
    checked_files = []

    for rel_path in REQUIRED_FILES:
        abs_path = os.path.join(root, rel_path)
        if not os.path.exists(abs_path):
            if strict_missing:
                findings.append({"rule": "STRICT_MISSING_FILE", "file": rel_path, "severity": "HIGH"})
            continue
        checked_files.append(rel_path)

    for rel_path, pattern, rule_id in FORBIDDEN_PATTERNS:
        abs_path = os.path.join(root, rel_path)
        if not os.path.exists(abs_path):
            continue
        with open(abs_path, "r", encoding="utf-8") as f:
            content = f.read()
        if re.search(pattern, content):
            findings.append({"rule": rule_id, "file": rel_path, "severity": "P0_OR_P1"})

    report = {
        "scanner": "security_gate.py",
        "strict_missing": strict_missing,
        "checked_files_count": len(checked_files),
        "findings_count": len(findings),
        "findings": findings,
        "static_pass": len(findings) == 0,
        "disclaimer": "Static pattern scanning PASS does NOT by itself guarantee complete runtime or operational security.",
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    sys.exit(0 if len(findings) == 0 else 1)


if __name__ == "__main__":
    main()

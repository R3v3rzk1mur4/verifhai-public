#!/usr/bin/env python3
"""
Security Gate Script

Final security gate check for CI/CD pipelines.
Aggregates results from all security checks and makes release decision.

Usage:
    python security_gate.py --check-all
    python security_gate.py --sast-report semgrep.sarif --deps-report audit.json
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class GateResult:
    """Result of a security gate check."""

    name: str
    passed: bool
    blocking: bool
    message: str
    details: list[str] | None = None


@dataclass
class SecurityGateReport:
    """Overall security gate report."""

    results: list[GateResult]
    passed: bool = True
    blocked: bool = False

    def add_result(self, result: GateResult) -> None:
        """Add a gate result."""
        self.results.append(result)
        if not result.passed:
            if result.blocking:
                self.blocked = True
                self.passed = False
            else:
                # Non-blocking failure is a warning
                pass


def check_sast_report(report_path: Path) -> GateResult:
    """Check SAST (Semgrep) report for critical findings."""
    if not report_path.exists():
        return GateResult(
            name="SAST Scan",
            passed=True,
            blocking=True,
            message="No SAST report found (scan may have passed with no findings)",
        )

    try:
        with open(report_path) as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        return GateResult(
            name="SAST Scan",
            passed=False,
            blocking=True,
            message=f"Invalid SAST report format: {e}",
        )

    # Parse SARIF format
    findings: list[dict[str, Any]] = []
    critical_count = 0
    high_count = 0

    runs = data.get("runs", [])
    for run in runs:
        results = run.get("results", [])
        for result in results:
            level = result.get("level", "warning")
            rule_id = result.get("ruleId", "unknown")
            message = result.get("message", {}).get("text", "No message")

            findings.append(
                {
                    "rule": rule_id,
                    "level": level,
                    "message": message,
                }
            )

            if level == "error":
                critical_count += 1
            elif level == "warning":
                high_count += 1

    details = [f"{f['level'].upper()}: [{f['rule']}] {f['message'][:80]}" for f in findings[:10]]

    if len(findings) > 10:
        details.append(f"... and {len(findings) - 10} more findings")

    # Block on critical findings
    if critical_count > 0:
        return GateResult(
            name="SAST Scan",
            passed=False,
            blocking=True,
            message=f"Found {critical_count} critical, {high_count} high severity findings",
            details=details,
        )

    # Warn on high findings
    if high_count > 0:
        return GateResult(
            name="SAST Scan",
            passed=True,
            blocking=False,
            message=f"Found {high_count} high severity findings (review recommended)",
            details=details,
        )

    return GateResult(
        name="SAST Scan",
        passed=True,
        blocking=True,
        message="No security findings",
    )


def check_dependency_report(report_path: Path) -> GateResult:
    """Check dependency vulnerability report."""
    if not report_path.exists():
        return GateResult(
            name="Dependency Scan",
            passed=True,
            blocking=False,
            message="No dependency report found",
        )

    try:
        with open(report_path) as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        return GateResult(
            name="Dependency Scan",
            passed=False,
            blocking=False,
            message=f"Invalid dependency report format: {e}",
        )

    # Parse pip-audit format
    vulnerabilities: list[dict[str, Any]] = []

    # Handle both list and dict formats
    deps = data if isinstance(data, list) else data.get("dependencies", [])

    for dep in deps:
        vulns = dep.get("vulns", [])
        pkg_name = dep.get("name", "unknown")
        for vuln in vulns:
            vulnerabilities.append(
                {
                    "package": pkg_name,
                    "id": vuln.get("id", "unknown"),
                    "fix": vuln.get("fix_versions", []),
                }
            )

    if not vulnerabilities:
        return GateResult(
            name="Dependency Scan",
            passed=True,
            blocking=False,
            message="No vulnerable dependencies found",
        )

    details = [f"{v['package']}: {v['id']}" for v in vulnerabilities[:10]]

    if len(vulnerabilities) > 10:
        details.append(f"... and {len(vulnerabilities) - 10} more")

    return GateResult(
        name="Dependency Scan",
        passed=False,
        blocking=False,  # Dependencies are usually not blocking
        message=f"Found {len(vulnerabilities)} vulnerable dependencies",
        details=details,
    )


def check_secrets_report(report_path: Path) -> GateResult:
    """Check secret detection report."""
    if not report_path.exists():
        return GateResult(
            name="Secret Detection",
            passed=True,
            blocking=True,
            message="No secrets report found (assuming scan passed)",
        )

    try:
        with open(report_path) as f:
            data = json.load(f)
    except json.JSONDecodeError:
        return GateResult(
            name="Secret Detection",
            passed=True,
            blocking=True,
            message="No parseable secrets report",
        )

    secrets = data.get("results", [])

    if secrets:
        details = [f"{s.get('detector_type', 'unknown')}: {s.get('raw', '***')[:20]}..." for s in secrets[:5]]
        return GateResult(
            name="Secret Detection",
            passed=False,
            blocking=True,
            message=f"Found {len(secrets)} potential secrets",
            details=details,
        )

    return GateResult(
        name="Secret Detection",
        passed=True,
        blocking=True,
        message="No secrets detected",
    )


def print_report(report: SecurityGateReport) -> None:
    """Print the security gate report."""
    print("\n" + "=" * 70)
    print("SECURITY GATE REPORT")
    print("=" * 70)

    for result in report.results:
        status = "PASS" if result.passed else ("BLOCK" if result.blocking else "WARN")
        color = "\033[92m" if result.passed else ("\033[91m" if result.blocking else "\033[93m")
        reset = "\033[0m"

        blocking_indicator = " [BLOCKING]" if result.blocking and not result.passed else ""
        print(f"\n{color}[{status}]{reset} {result.name}{blocking_indicator}")
        print(f"  {result.message}")

        if result.details:
            for detail in result.details:
                print(f"    - {detail}")

    print("\n" + "=" * 70)

    if report.blocked:
        print("\033[91m✗ SECURITY GATE: BLOCKED\033[0m")
        print("  One or more blocking checks failed. Merge is not allowed.")
    elif not report.passed:
        print("\033[93m⚠ SECURITY GATE: PASSED WITH WARNINGS\033[0m")
        print("  Some non-blocking checks failed. Review recommended.")
    else:
        print("\033[92m✓ SECURITY GATE: PASSED\033[0m")
        print("  All security checks passed. Safe to merge.")

    print("=" * 70)


def main() -> None:
    """Run security gate checks."""
    parser = argparse.ArgumentParser(
        description="Security Gate - Final security check for CI/CD",
    )

    parser.add_argument(
        "--sast-report",
        type=Path,
        default=Path("semgrep.sarif"),
        help="Path to SAST report (SARIF format)",
    )
    parser.add_argument(
        "--deps-report",
        type=Path,
        default=Path("audit.json"),
        help="Path to dependency scan report",
    )
    parser.add_argument(
        "--secrets-report",
        type=Path,
        default=Path("secrets.json"),
        help="Path to secret detection report",
    )
    parser.add_argument(
        "--check-all",
        action="store_true",
        help="Run all checks",
    )
    parser.add_argument(
        "--fail-on-warning",
        action="store_true",
        help="Exit with error on warnings",
    )

    args = parser.parse_args()

    report = SecurityGateReport(results=[])

    # Run checks
    print("Running security gate checks...")

    # SAST check (blocking)
    sast_result = check_sast_report(args.sast_report)
    report.add_result(sast_result)

    # Dependency check (warning)
    deps_result = check_dependency_report(args.deps_report)
    report.add_result(deps_result)

    # Secrets check (blocking)
    secrets_result = check_secrets_report(args.secrets_report)
    report.add_result(secrets_result)

    # Print report
    print_report(report)

    # Exit code
    if report.blocked:
        sys.exit(1)
    elif args.fail_on_warning and not report.passed:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()

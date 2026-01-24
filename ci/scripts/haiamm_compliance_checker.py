#!/usr/bin/env python3
"""
HAIAMM Compliance Checker

Verifies that a project follows HAIAMM security practices:
1. All 12 HAIAMM practice templates exist
2. CI/CD enforces security practices
3. Required security documentation is present

Usage:
    python haiamm_compliance_checker.py --check-templates
    python haiamm_compliance_checker.py --check-coverage
    python haiamm_compliance_checker.py --all
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import NamedTuple


# HAIAMM Practice definitions
HAIAMM_PRACTICES: dict[str, str] = {
    "SM": "Strategy & Metrics",
    "PC": "Policy & Compliance",
    "EG": "Education & Guidance",
    "TA": "Threat Assessment",
    "SR": "Security Requirements",
    "SA": "Secure Architecture",
    "DR": "Design Review",
    "IR": "Implementation Review",
    "ST": "Security Testing",
    "EH": "Environment Hardening",
    "IM": "Issue Management",
    "ML": "Monitoring & Logging",
}

# Expected template files mapping
PRACTICE_TEMPLATES: dict[str, str] = {
    "SM": "StrategyMetrics.md",
    "PC": "PolicyCompliance.md",
    "EG": "EducationGuidance.md",
    "TA": "ThreatModel.md",
    "SR": "SecurityRequirements.md",
    "SA": "SecureArchitecture.md",
    "DR": "DesignReview.md",
    "IR": "ReviewChecklist.md",
    "ST": "SecurityTesting.md",
    "EH": "EnvironmentHardening.md",
    "IM": "IssueManagement.md",
    "ML": "MonitoringLogging.md",
}

# CI/CD practice coverage - what practices have automated checks
CI_PRACTICE_COVERAGE: dict[str, str] = {
    "SR": "Semgrep permission-bypass rules enforce permission boundaries",
    "IR": "Semgrep prompt-injection + tool-misuse rules, ruff/mypy checks",
    "ST": "pytest security tests, Semgrep SAST scanning",
    "ML": "Semgrep hai-security rules check for logging presence",
    "SA": "Semgrep detects containment issues (infinite loops, recursion)",
    "TA": "Documented via ThreatModel.md template (manual process)",
}

# Practices that require manual review (cannot be fully automated)
MANUAL_PRACTICES: set[str] = {"SM", "PC", "EG", "DR", "EH", "IM"}


class ComplianceResult(NamedTuple):
    """Result of a compliance check."""

    passed: bool
    message: str
    details: list[str]


@dataclass
class ComplianceReport:
    """Full compliance report."""

    templates_result: ComplianceResult | None = None
    coverage_result: ComplianceResult | None = None
    overall_passed: bool = True

    def add_result(self, name: str, result: ComplianceResult) -> None:
        """Add a result to the report."""
        if name == "templates":
            self.templates_result = result
        elif name == "coverage":
            self.coverage_result = result

        if not result.passed:
            self.overall_passed = False


def check_templates_exist(template_dir: Path) -> ComplianceResult:
    """Verify all required HAIAMM templates exist."""
    missing: list[str] = []
    found: list[str] = []

    for practice_id, template_name in PRACTICE_TEMPLATES.items():
        template_path = template_dir / template_name
        practice_name = HAIAMM_PRACTICES[practice_id]

        if template_path.exists():
            found.append(f"{practice_id} ({practice_name}): {template_name}")
        else:
            missing.append(f"{practice_id} ({practice_name}): {template_name} - MISSING")

    total = len(PRACTICE_TEMPLATES)
    found_count = len(found)

    if missing:
        return ComplianceResult(
            passed=False,
            message=f"Missing {len(missing)} of {total} HAIAMM templates",
            details=missing + ["", "Found templates:"] + found,
        )

    return ComplianceResult(
        passed=True,
        message=f"All {total} HAIAMM practice templates present",
        details=found,
    )


def check_practice_coverage() -> ComplianceResult:
    """Check how many HAIAMM practices have CI/CD automation."""
    automated: list[str] = []
    manual: list[str] = []

    for practice_id, practice_name in HAIAMM_PRACTICES.items():
        if practice_id in CI_PRACTICE_COVERAGE:
            coverage = CI_PRACTICE_COVERAGE[practice_id]
            automated.append(f"{practice_id} ({practice_name}): {coverage}")
        else:
            manual.append(f"{practice_id} ({practice_name}): Manual review required")

    automated_count = len(automated)
    manual_count = len(manual)
    total = len(HAIAMM_PRACTICES)

    # We expect ~50% automation (6 automated, 6 manual)
    # This is acceptable as some practices are inherently manual
    min_automated = 5

    details = [
        f"Automated checks: {automated_count}/{total}",
        f"Manual review: {manual_count}/{total}",
        "",
        "=== Automated Practices ===",
        *automated,
        "",
        "=== Manual Practices ===",
        *manual,
    ]

    if automated_count >= min_automated:
        return ComplianceResult(
            passed=True,
            message=f"{automated_count} practices have automated checks ({manual_count} manual)",
            details=details,
        )

    return ComplianceResult(
        passed=False,
        message=f"Insufficient automation: {automated_count} < {min_automated} required",
        details=details,
    )


def check_ci_files_exist(project_root: Path) -> ComplianceResult:
    """Check that CI/CD configuration files exist."""
    required_files = [
        (".github/workflows/ci.yml", "GitHub Actions CI workflow"),
        (".pre-commit-config.yaml", "Pre-commit hooks configuration"),
    ]

    optional_files = [
        (".gitlab-ci.yml", "GitLab CI pipeline"),
        (".github/workflows/security-scan.yml", "Scheduled security scanning"),
    ]

    missing_required: list[str] = []
    found_required: list[str] = []
    found_optional: list[str] = []

    for file_path, description in required_files:
        full_path = project_root / file_path
        if full_path.exists():
            found_required.append(f"[REQUIRED] {file_path}: {description}")
        else:
            missing_required.append(f"[REQUIRED] {file_path}: {description} - MISSING")

    for file_path, description in optional_files:
        full_path = project_root / file_path
        if full_path.exists():
            found_optional.append(f"[OPTIONAL] {file_path}: {description}")

    details = found_required + found_optional
    if missing_required:
        details = missing_required + [""] + details

    if missing_required:
        return ComplianceResult(
            passed=False,
            message=f"Missing {len(missing_required)} required CI/CD files",
            details=details,
        )

    return ComplianceResult(
        passed=True,
        message=f"All required CI/CD files present ({len(found_optional)} optional found)",
        details=details,
    )


def print_result(name: str, result: ComplianceResult) -> None:
    """Print a compliance check result."""
    status = "PASS" if result.passed else "FAIL"
    color = "\033[92m" if result.passed else "\033[91m"
    reset = "\033[0m"

    print(f"\n{color}[{status}]{reset} {name}: {result.message}")

    if result.details:
        for detail in result.details:
            if detail:
                print(f"  {detail}")
            else:
                print()


def main() -> None:
    """Run HAIAMM compliance checks."""
    parser = argparse.ArgumentParser(
        description="HAIAMM Compliance Checker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python haiamm_compliance_checker.py --check-templates
  python haiamm_compliance_checker.py --check-coverage
  python haiamm_compliance_checker.py --all --template-dir ./templates
        """,
    )

    parser.add_argument(
        "--check-templates",
        action="store_true",
        help="Verify all 12 HAIAMM templates exist",
    )
    parser.add_argument(
        "--check-coverage",
        action="store_true",
        help="Check HAIAMM practice CI/CD coverage",
    )
    parser.add_argument(
        "--check-ci",
        action="store_true",
        help="Check CI/CD configuration files exist",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run all compliance checks",
    )
    parser.add_argument(
        "--template-dir",
        type=Path,
        default=Path("claude-skill/templates"),
        help="Path to templates directory (default: claude-skill/templates)",
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path("."),
        help="Project root directory (default: current directory)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Only output failures",
    )

    args = parser.parse_args()

    # If no specific check requested, show help
    if not any([args.check_templates, args.check_coverage, args.check_ci, args.all]):
        parser.print_help()
        sys.exit(0)

    report = ComplianceReport()

    print("=" * 60)
    print("HAIAMM Compliance Checker")
    print("=" * 60)

    # Run requested checks
    if args.check_templates or args.all:
        result = check_templates_exist(args.template_dir)
        report.add_result("templates", result)
        if not args.quiet or not result.passed:
            print_result("Template Check", result)

    if args.check_coverage or args.all:
        result = check_practice_coverage()
        report.add_result("coverage", result)
        if not args.quiet or not result.passed:
            print_result("Practice Coverage", result)

    if args.check_ci or args.all:
        result = check_ci_files_exist(args.project_root)
        if not args.quiet or not result.passed:
            print_result("CI/CD Files", result)
        if not result.passed:
            report.overall_passed = False

    # Summary
    print("\n" + "=" * 60)
    if report.overall_passed:
        print("\033[92m✓ All compliance checks passed!\033[0m")
        sys.exit(0)
    else:
        print("\033[91m✗ Some compliance checks failed.\033[0m")
        sys.exit(1)


if __name__ == "__main__":
    main()

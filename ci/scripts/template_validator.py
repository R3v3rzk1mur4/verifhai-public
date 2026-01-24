#!/usr/bin/env python3
"""
HAIAMM Template Validator

Validates that HAIAMM templates follow the required schema:
1. Document Control section present
2. Proper markdown structure
3. HAIAMM practice references
4. Required sections present

Usage:
    python template_validator.py <template_path_or_directory>
    python template_validator.py claude-skill/templates/
    python template_validator.py claude-skill/templates/SecurityRequirements.md
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ValidationError:
    """A validation error found in a template."""

    severity: str  # ERROR, WARNING, INFO
    message: str
    line_number: int | None = None


@dataclass
class ValidationResult:
    """Result of validating a template."""

    file_path: Path
    is_valid: bool
    errors: list[ValidationError] = field(default_factory=list)
    warnings: list[ValidationError] = field(default_factory=list)
    info: list[ValidationError] = field(default_factory=list)


# Required sections for HAIAMM templates
REQUIRED_SECTIONS = [
    "Document Control",
]

# Recommended sections (warning if missing)
RECOMMENDED_SECTIONS = [
    "Revision History",
]

# Keywords that indicate HAIAMM relevance
HAIAMM_KEYWORDS = [
    "HAIAMM",
    "HAI",
    "Human-Assisted Intelligence",
    "Practice",
    "Maturity",
]

# AI threat keywords
AI_THREAT_KEYWORDS = [
    "EA",
    "Excessive Agency",
    "AGH",
    "Agent Goal Hijacking",
    "TM",
    "Tool Misuse",
    "RA",
    "Rogue Agent",
    "Prompt Injection",
]


def validate_document_control(content: str, lines: list[str]) -> list[ValidationError]:
    """Validate the Document Control section."""
    errors: list[ValidationError] = []

    # Check for Document Control section
    if "## Document Control" not in content:
        errors.append(
            ValidationError(
                severity="ERROR",
                message="Missing '## Document Control' section",
            )
        )
        return errors

    # Find the Document Control section
    in_doc_control = False
    doc_control_lines: list[tuple[int, str]] = []

    for i, line in enumerate(lines, 1):
        if "## Document Control" in line:
            in_doc_control = True
            continue
        if in_doc_control:
            if line.startswith("## ") or line.startswith("# "):
                break
            doc_control_lines.append((i, line))

    # Check for table format
    has_table = any("|" in line for _, line in doc_control_lines)
    if not has_table:
        errors.append(
            ValidationError(
                severity="WARNING",
                message="Document Control section should use table format",
            )
        )

    # Check for required fields in Document Control
    required_fields = ["Project", "Version", "Date", "Status"]
    doc_control_text = "\n".join(line for _, line in doc_control_lines)

    for field_name in required_fields:
        if field_name.lower() not in doc_control_text.lower():
            errors.append(
                ValidationError(
                    severity="WARNING",
                    message=f"Document Control missing field: {field_name}",
                )
            )

    return errors


def validate_structure(content: str, lines: list[str]) -> list[ValidationError]:
    """Validate the overall markdown structure."""
    errors: list[ValidationError] = []

    # Check for H1 title
    if not content.startswith("# "):
        errors.append(
            ValidationError(
                severity="ERROR",
                message="Template must start with H1 title (# Title)",
                line_number=1,
            )
        )

    # Check for numbered sections
    section_pattern = re.compile(r"^## \d+\.")
    has_numbered_sections = any(section_pattern.match(line) for line in lines)

    if not has_numbered_sections:
        errors.append(
            ValidationError(
                severity="WARNING",
                message="Template should have numbered sections (## 1. Section Name)",
            )
        )

    # Check for empty sections (heading with no content)
    for i, line in enumerate(lines):
        if line.startswith("## ") or line.startswith("### "):
            # Check if next non-empty line is another heading
            for j in range(i + 1, min(i + 5, len(lines))):
                next_line = lines[j].strip()
                if next_line:
                    if next_line.startswith("#"):
                        errors.append(
                            ValidationError(
                                severity="INFO",
                                message=f"Section may be empty: {line.strip()}",
                                line_number=i + 1,
                            )
                        )
                    break

    return errors


def validate_haiamm_references(content: str) -> list[ValidationError]:
    """Check for HAIAMM-related content."""
    errors: list[ValidationError] = []

    # Check for HAIAMM keywords
    has_haiamm = any(keyword.lower() in content.lower() for keyword in HAIAMM_KEYWORDS)

    if not has_haiamm:
        errors.append(
            ValidationError(
                severity="WARNING",
                message="Template should reference HAIAMM framework or practices",
            )
        )

    # Check for AI threat references (for security templates)
    has_ai_threats = any(keyword.lower() in content.lower() for keyword in AI_THREAT_KEYWORDS)

    # This is informational - not all templates need to reference threats
    if has_ai_threats:
        errors.append(
            ValidationError(
                severity="INFO",
                message="Template includes AI-specific threat references (good!)",
            )
        )

    return errors


def validate_revision_history(content: str) -> list[ValidationError]:
    """Check for Revision History section."""
    errors: list[ValidationError] = []

    if "## Revision History" not in content:
        errors.append(
            ValidationError(
                severity="INFO",
                message="Consider adding '## Revision History' section for change tracking",
            )
        )

    return errors


def validate_template(file_path: Path) -> ValidationResult:
    """Validate a single template file."""
    errors: list[ValidationError] = []
    warnings: list[ValidationError] = []
    info: list[ValidationError] = []

    try:
        content = file_path.read_text(encoding="utf-8")
        lines = content.split("\n")
    except Exception as e:
        return ValidationResult(
            file_path=file_path,
            is_valid=False,
            errors=[ValidationError(severity="ERROR", message=f"Cannot read file: {e}")],
        )

    # Run all validations
    all_issues: list[ValidationError] = []
    all_issues.extend(validate_document_control(content, lines))
    all_issues.extend(validate_structure(content, lines))
    all_issues.extend(validate_haiamm_references(content))
    all_issues.extend(validate_revision_history(content))

    # Categorize by severity
    for issue in all_issues:
        if issue.severity == "ERROR":
            errors.append(issue)
        elif issue.severity == "WARNING":
            warnings.append(issue)
        else:
            info.append(issue)

    # Template is valid if no errors (warnings are ok)
    is_valid = len(errors) == 0

    return ValidationResult(
        file_path=file_path,
        is_valid=is_valid,
        errors=errors,
        warnings=warnings,
        info=info,
    )


def print_result(result: ValidationResult, verbose: bool = False) -> None:
    """Print validation result."""
    status = "PASS" if result.is_valid else "FAIL"
    color = "\033[92m" if result.is_valid else "\033[91m"
    reset = "\033[0m"
    yellow = "\033[93m"
    blue = "\033[94m"

    print(f"\n{color}[{status}]{reset} {result.file_path.name}")

    # Always show errors
    for error in result.errors:
        line_info = f" (line {error.line_number})" if error.line_number else ""
        print(f"  {color}ERROR{reset}{line_info}: {error.message}")

    # Show warnings
    for warning in result.warnings:
        line_info = f" (line {warning.line_number})" if warning.line_number else ""
        print(f"  {yellow}WARNING{reset}{line_info}: {warning.message}")

    # Show info only in verbose mode
    if verbose:
        for info_item in result.info:
            line_info = f" (line {info_item.line_number})" if info_item.line_number else ""
            print(f"  {blue}INFO{reset}{line_info}: {info_item.message}")


def main() -> None:
    """Run template validation."""
    parser = argparse.ArgumentParser(
        description="HAIAMM Template Validator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "path",
        type=Path,
        nargs="?",
        default=Path("claude-skill/templates"),
        help="Template file or directory to validate",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show INFO-level messages",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat warnings as errors",
    )

    args = parser.parse_args()

    # Collect files to validate
    files_to_validate: list[Path] = []

    if args.path.is_file():
        files_to_validate.append(args.path)
    elif args.path.is_dir():
        files_to_validate.extend(args.path.glob("*.md"))
    else:
        print(f"Error: Path not found: {args.path}")
        sys.exit(1)

    if not files_to_validate:
        print(f"No .md files found in {args.path}")
        sys.exit(1)

    print("=" * 60)
    print("HAIAMM Template Validator")
    print("=" * 60)
    print(f"Validating {len(files_to_validate)} template(s)...")

    # Validate all files
    results: list[ValidationResult] = []
    for file_path in sorted(files_to_validate):
        result = validate_template(file_path)
        results.append(result)
        print_result(result, verbose=args.verbose)

    # Summary
    passed = sum(1 for r in results if r.is_valid)
    failed = len(results) - passed
    total_errors = sum(len(r.errors) for r in results)
    total_warnings = sum(len(r.warnings) for r in results)

    print("\n" + "=" * 60)
    print(f"Summary: {passed}/{len(results)} templates valid")
    print(f"  Errors: {total_errors}")
    print(f"  Warnings: {total_warnings}")

    # Exit code
    if failed > 0:
        print("\n\033[91m✗ Validation failed.\033[0m")
        sys.exit(1)
    elif args.strict and total_warnings > 0:
        print("\n\033[93m✗ Validation failed (strict mode, warnings present).\033[0m")
        sys.exit(1)
    else:
        print("\n\033[92m✓ All templates valid.\033[0m")
        sys.exit(0)


if __name__ == "__main__":
    main()

"""
HAIAMM - Human-Assisted Intelligence Application Maturity Model

Core framework definitions including practices, domains, and maturity levels.
"""

from typing import TypedDict


class Practice(TypedDict):
    """HAIAMM Security Practice."""
    id: str
    name: str
    description: str
    category: str
    ai_threats: list[str]


class Domain(TypedDict):
    """HAIAMM Security Domain."""
    id: str
    name: str
    description: str


class MaturityLevel(TypedDict):
    """HAIAMM Maturity Level."""
    level: int
    name: str
    description: str


class AIThreat(TypedDict):
    """AI-Specific Threat."""
    id: str
    name: str
    description: str
    mitigating_practices: list[str]


# =============================================================================
# HAIAMM PRACTICES (12 Total)
# =============================================================================

PRACTICES: list[Practice] = [
    # Governance
    {
        "id": "SM",
        "name": "Strategy & Metrics",
        "description": "Establish security strategy, goals, and key performance indicators for HAI systems",
        "category": "governance",
        "ai_threats": [],
    },
    {
        "id": "PC",
        "name": "Policy & Compliance",
        "description": "Define policies, standards, and ensure regulatory compliance for AI systems",
        "category": "governance",
        "ai_threats": [],
    },
    {
        "id": "EG",
        "name": "Education & Guidance",
        "description": "Provide security training, awareness, and guidance for AI development teams",
        "category": "governance",
        "ai_threats": [],
    },
    # Design
    {
        "id": "TA",
        "name": "Threat Assessment",
        "description": "Identify and analyze threats specific to AI systems including adversarial attacks",
        "category": "design",
        "ai_threats": ["EA", "AGH", "TM", "RA"],
    },
    {
        "id": "SR",
        "name": "Security Requirements",
        "description": "Define security requirements including permission boundaries and constraints",
        "category": "design",
        "ai_threats": ["EA", "AGH", "TM"],
    },
    {
        "id": "SA",
        "name": "Secure Architecture",
        "description": "Design secure architecture patterns for AI systems with defense in depth",
        "category": "design",
        "ai_threats": ["EA", "AGH", "RA"],
    },
    # Verification
    {
        "id": "DR",
        "name": "Design Review",
        "description": "Review architecture and design for security vulnerabilities before implementation",
        "category": "verification",
        "ai_threats": [],
    },
    {
        "id": "IR",
        "name": "Implementation Review",
        "description": "Review code and configuration for security issues including prompt injection",
        "category": "verification",
        "ai_threats": ["AGH", "TM"],
    },
    {
        "id": "ST",
        "name": "Security Testing",
        "description": "Test AI systems for vulnerabilities including adversarial robustness testing",
        "category": "verification",
        "ai_threats": ["AGH", "TM"],
    },
    # Operations
    {
        "id": "EH",
        "name": "Environment Hardening",
        "description": "Secure the infrastructure and environment hosting AI systems",
        "category": "operations",
        "ai_threats": [],
    },
    {
        "id": "IM",
        "name": "Issue Management",
        "description": "Track and remediate security vulnerabilities in AI systems",
        "category": "operations",
        "ai_threats": ["RA"],
    },
    {
        "id": "ML",
        "name": "Monitoring & Logging",
        "description": "Monitor AI system behavior and maintain audit logs for detection and response",
        "category": "operations",
        "ai_threats": ["EA", "AGH", "RA"],
    },
]


# =============================================================================
# HAIAMM DOMAINS (6 Total)
# =============================================================================

DOMAINS: list[Domain] = [
    {
        "id": "SOFTWARE",
        "name": "Software",
        "description": "AI applications, models, and code security",
    },
    {
        "id": "DATA",
        "name": "Data",
        "description": "Training data, operational data, and privacy protection",
    },
    {
        "id": "INFRASTRUCTURE",
        "name": "Infrastructure",
        "description": "Cloud and on-premise deployment security",
    },
    {
        "id": "VENDORS",
        "name": "Vendors",
        "description": "Third-party HAI services and supply chain security",
    },
    {
        "id": "PROCESSES",
        "name": "Processes",
        "description": "Business workflows and governance processes",
    },
    {
        "id": "ENDPOINTS",
        "name": "Endpoints",
        "description": "User interfaces, APIs, and access points",
    },
]


# =============================================================================
# MATURITY LEVELS (3 Total)
# =============================================================================

MATURITY_LEVELS: list[MaturityLevel] = [
    {
        "level": 1,
        "name": "Foundational",
        "description": "Essential security basics that everyone needs",
    },
    {
        "level": 2,
        "name": "Comprehensive",
        "description": "Structured practices for maturing security teams",
    },
    {
        "level": 3,
        "name": "Industry-Leading",
        "description": "Optimized practices for security-conscious organizations",
    },
]


# =============================================================================
# AI-SPECIFIC THREATS
# =============================================================================

AI_THREATS: list[AIThreat] = [
    {
        "id": "EA",
        "name": "Excessive Agency",
        "description": "AI system has more permissions or capabilities than needed for its task",
        "mitigating_practices": ["TA", "SR", "SA", "ML"],
    },
    {
        "id": "AGH",
        "name": "Agent Goal Hijacking",
        "description": "AI system's goals or behavior are manipulated through adversarial inputs",
        "mitigating_practices": ["TA", "SR", "SA", "IR", "ST", "ML"],
    },
    {
        "id": "TM",
        "name": "Tool Misuse",
        "description": "AI system's tools or capabilities are used for unintended malicious purposes",
        "mitigating_practices": ["TA", "SR", "IR", "ST"],
    },
    {
        "id": "RA",
        "name": "Rogue Agent",
        "description": "AI system acts autonomously in unexpected or harmful ways",
        "mitigating_practices": ["TA", "SA", "IM", "ML"],
    },
]


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def get_practice_by_id(practice_id: str) -> Practice | None:
    """Get a practice by its ID (case-insensitive)."""
    practice_id_upper = practice_id.upper()
    for practice in PRACTICES:
        if practice["id"] == practice_id_upper:
            return practice
    return None


def get_domain_by_id(domain_id: str) -> Domain | None:
    """Get a domain by its ID (case-insensitive)."""
    domain_id_upper = domain_id.upper()
    for domain in DOMAINS:
        if domain["id"] == domain_id_upper:
            return domain
    return None


def get_practices_for_threat(threat_id: str) -> list[Practice]:
    """Get all practices that mitigate a specific AI threat."""
    threat = next((t for t in AI_THREATS if t["id"] == threat_id.upper()), None)
    if not threat:
        return []
    return [p for p in PRACTICES if p["id"] in threat["mitigating_practices"]]


def get_practices_by_category(category: str) -> list[Practice]:
    """Get all practices in a category (governance, design, verification, operations)."""
    return [p for p in PRACTICES if p["category"] == category.lower()]

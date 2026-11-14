"""
Compliance Scoring System
==========================
Calculates compliance scores with breakdowns by level, severity, and category.

Parche de compatibilidad (Lab Hardening-CIS 2025-0813)
-----------------------------------------------------
En el repositorio original, reporting/html_report.py, remediation.py y
web/app.py ya usan el modelo con controles "MANUAL_REVIEW"
(report.evaluated_rules, report.manual_review_rules,
report.manual_review_results, report.level1 / report.level2, report.severity
y CategoryScore.manual_review), pero este scoring.py no se había actualizado.
Por eso la generación del informe HTML terminaba con AttributeError y la
carpeta de salida quedaba vacía.

Este archivo añade esos atributos sin quitar ninguno de los anteriores.
Los controles en MANUAL_REVIEW ya no se cuentan como fallos: se excluyen de
los porcentajes y de la puntuación ponderada, como explica el propio informe.
"""

from dataclasses import dataclass, field
from typing import List, Dict
from cis_benchmark.rules.base import RuleResult, RuleStatus, CISLevel, RuleSeverity


def _pct(passed: int, evaluated: int) -> float:
    return round((passed / evaluated) * 100, 1) if evaluated > 0 else 0.0


def _is_manual(result: RuleResult) -> bool:
    return result.status == RuleStatus.MANUAL_REVIEW


@dataclass
class Breakdown:
    """Counts for a group of controls (one CIS level or one severity)."""
    total: int = 0
    passed: int = 0
    failed: int = 0
    manual_review: int = 0

    @property
    def evaluated(self) -> int:
        return self.passed + self.failed

    @property
    def percentage(self) -> float:
        return _pct(self.passed, self.evaluated)

    def to_dict(self) -> dict:
        return {
            "total": self.total,
            "evaluated": self.evaluated,
            "passed": self.passed,
            "failed": self.failed,
            "manual_review": self.manual_review,
            "percentage": self.percentage,
        }


@dataclass
class CategoryScore:
    """Score for a specific category."""
    category: str
    total: int = 0
    passed: int = 0
    failed: int = 0
    manual_review: int = 0

    @property
    def evaluated(self) -> int:
        return self.passed + self.failed

    @property
    def percentage(self) -> float:
        return _pct(self.passed, self.evaluated)


@dataclass
class ComplianceReport:
    """Complete compliance scoring report."""
    # Overall
    total_rules: int = 0            # every control, manual review included
    passed_rules: int = 0
    failed_rules: int = 0           # FAIL or ERROR (manual review excluded)
    evaluated_rules: int = 0        # passed + failed
    manual_review_rules: int = 0
    overall_percentage: float = 0.0  # passed / evaluated
    risk_rating: str = "Unknown"
    risk_color: str = "#6c757d"

    # By Level
    level1_total: int = 0
    level1_passed: int = 0
    level1_percentage: float = 0.0
    level2_total: int = 0
    level2_passed: int = 0
    level2_percentage: float = 0.0
    level1: Breakdown = field(default_factory=Breakdown)
    level2: Breakdown = field(default_factory=Breakdown)

    # By Severity
    critical_total: int = 0
    critical_passed: int = 0
    critical_percentage: float = 0.0
    high_total: int = 0
    high_passed: int = 0
    high_percentage: float = 0.0
    medium_total: int = 0
    medium_passed: int = 0
    medium_percentage: float = 0.0
    low_total: int = 0
    low_passed: int = 0
    low_percentage: float = 0.0
    severity: Dict[str, Breakdown] = field(default_factory=dict)  # keyed "Critical", "High", ...

    # By Category
    category_scores: Dict[str, CategoryScore] = field(default_factory=dict)

    # Weighted score
    weighted_score: float = 0.0

    # Results
    results: List[RuleResult] = field(default_factory=list)
    failed_results: List[RuleResult] = field(default_factory=list)
    passed_results: List[RuleResult] = field(default_factory=list)
    manual_review_results: List[RuleResult] = field(default_factory=list)

    # Severity breakdown for failed rules
    critical_failures: List[RuleResult] = field(default_factory=list)
    high_failures: List[RuleResult] = field(default_factory=list)
    medium_failures: List[RuleResult] = field(default_factory=list)
    low_failures: List[RuleResult] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "summary": {
                "total_rules": self.total_rules,
                "evaluated_rules": self.evaluated_rules,
                "passed_rules": self.passed_rules,
                "failed_rules": self.failed_rules,
                "manual_review_rules": self.manual_review_rules,
                "overall_percentage": self.overall_percentage,
                "weighted_score": self.weighted_score,
                "risk_rating": self.risk_rating,
            },
            "level_breakdown": {
                "level1": self.level1.to_dict(),
                "level2": self.level2.to_dict(),
            },
            "severity_breakdown": {
                name.lower(): b.to_dict() for name, b in self.severity.items()
            },
            "category_breakdown": {
                name: {
                    "total": cs.total,
                    "evaluated": cs.evaluated,
                    "passed": cs.passed,
                    "failed": cs.failed,
                    "manual_review": cs.manual_review,
                    "percentage": cs.percentage,
                }
                for name, cs in self.category_scores.items()
            },
            "results": [r.to_dict() for r in self.results],
        }


class ComplianceScorer:
    """
    Calculates comprehensive compliance scores from rule results.

    Usage:
        scorer = ComplianceScorer()
        report = scorer.calculate(results)
        print(f"Score: {report.overall_percentage}%")
        print(f"Risk: {report.risk_rating}")
    """

    RISK_RATINGS = [
        (0, 40, "Critical", "#dc3545"),
        (40, 60, "High", "#fd7e14"),
        (60, 80, "Medium", "#ffc107"),
        (80, 101, "Low", "#28a745"),
    ]

    SEVERITY_PREFIXES = [
        (RuleSeverity.CRITICAL, "critical"),
        (RuleSeverity.HIGH, "high"),
        (RuleSeverity.MEDIUM, "medium"),
        (RuleSeverity.LOW, "low"),
    ]

    def calculate(self, results: List[RuleResult]) -> ComplianceReport:
        """Calculate compliance report from rule results."""
        report = ComplianceReport()
        report.results = results

        if not results:
            return report

        # Separate passed / failed / manual review
        report.passed_results = [r for r in results if r.passed]
        report.manual_review_results = [r for r in results if _is_manual(r)]
        report.failed_results = [r for r in results if not r.passed and not _is_manual(r)]

        # Overall counts (percentages only over evaluated controls)
        report.total_rules = len(results)
        report.passed_rules = len(report.passed_results)
        report.failed_rules = len(report.failed_results)
        report.manual_review_rules = len(report.manual_review_results)
        report.evaluated_rules = report.passed_rules + report.failed_rules
        report.overall_percentage = _pct(report.passed_rules, report.evaluated_rules)

        # Level breakdown
        report.level1 = self._breakdown([r for r in results if r.level == CISLevel.LEVEL_1])
        report.level2 = self._breakdown([r for r in results if r.level == CISLevel.LEVEL_2])
        report.level1_total = report.level1.total
        report.level1_passed = report.level1.passed
        report.level1_percentage = report.level1.percentage
        report.level2_total = report.level2.total
        report.level2_passed = report.level2.passed
        report.level2_percentage = report.level2.percentage

        # Severity breakdown
        self._calculate_severity(results, report)

        # Category breakdown
        self._calculate_categories(results, report)

        # Weighted score (severity-weighted, evaluated controls only)
        report.weighted_score = self._calculate_weighted_score(results)

        # Risk rating
        for low, high, rating, color in self.RISK_RATINGS:
            if low <= report.weighted_score < high:
                report.risk_rating = rating
                report.risk_color = color
                break

        return report

    @staticmethod
    def _breakdown(results: List[RuleResult]) -> Breakdown:
        b = Breakdown(total=len(results))
        for r in results:
            if r.passed:
                b.passed += 1
            elif _is_manual(r):
                b.manual_review += 1
            else:
                b.failed += 1
        return b

    def _calculate_severity(self, results: List[RuleResult], report: ComplianceReport):
        """Calculate severity-level breakdowns."""
        report.severity = {}
        for sev, prefix in self.SEVERITY_PREFIXES:
            group = [r for r in results if r.severity == sev]
            b = self._breakdown(group)
            report.severity[sev.value] = b
            setattr(report, f"{prefix}_total", b.total)
            setattr(report, f"{prefix}_passed", b.passed)
            setattr(report, f"{prefix}_percentage", b.percentage)
            setattr(report, f"{prefix}_failures",
                    [r for r in group if not r.passed and not _is_manual(r)])

    def _calculate_categories(self, results: List[RuleResult], report: ComplianceReport):
        """Calculate category-level breakdowns."""
        categories: Dict[str, CategoryScore] = {}

        for result in results:
            cat = result.category or "Uncategorized"
            if cat not in categories:
                categories[cat] = CategoryScore(category=cat)
            categories[cat].total += 1
            if result.passed:
                categories[cat].passed += 1
            elif _is_manual(result):
                categories[cat].manual_review += 1
            else:
                categories[cat].failed += 1

        report.category_scores = dict(sorted(categories.items()))

    def _calculate_weighted_score(self, results: List[RuleResult]) -> float:
        """Calculate severity-weighted compliance score (manual review excluded)."""
        total_weight = 0
        earned_weight = 0

        for result in results:
            if _is_manual(result):
                continue
            weight = result.severity.weight
            total_weight += weight
            if result.passed:
                earned_weight += weight

        if total_weight == 0:
            return 0.0
        return round((earned_weight / total_weight) * 100, 1)

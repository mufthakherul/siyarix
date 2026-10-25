# SPDX-License-Identifier: AGPL-3.0-or-later
"""SX-011: CVSS 3.1 Roundup, PR scope weights, informational findings."""

from __future__ import annotations

import pytest

from siyarix.cvss_scorer import CVSSScorer, Severity, roundup


@pytest.fixture
def scorer():
    return CVSSScorer()


class TestSX011CVSS31:
    def test_example_vector_scores_6_5_not_6_4(self, scorer):
        # FIRST example: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L → 6.5
        vector = scorer.parse_vector_string(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L"
        )
        result = scorer.score(vector)
        assert result.score == 6.5
        assert result.severity == Severity.MEDIUM

    def test_roundup_not_half_up_round(self):
        # 6.401… must Roundup to 6.5, not round to 6.4
        assert roundup(6.401114775) == 6.5
        assert roundup(4.0) == 4.0
        assert roundup(4.01) == 4.1

    def test_pr_weights_scope_changed_vs_unchanged(self, scorer):
        # Same metrics except scope; Scope Changed uses PR Low=0.68 not 0.62
        base = dict(
            attack_vector="network",
            attack_complexity="low",
            privileges_required="low",
            user_interaction="none",
            confidentiality="high",
            integrity="high",
            availability="none",
        )
        unchanged = scorer.score(scope="unchanged", **base)
        changed = scorer.score(scope="changed", **base)
        assert unchanged.score is not None and changed.score is not None
        assert changed.score != unchanged.score
        # Scope Changed with PR:L must score higher exploitability contribution
        assert changed.score > unchanged.score

    def test_informational_finding_not_critical(self, scorer):
        result = scorer.score_from_finding(
            {
                "title": "Banner information disclosure",
                "description": "Server returns version banner",
                "severity": "informational",
            }
        )
        assert result.unknown is True
        assert result.score is None
        assert result.severity == Severity.UNKNOWN
        assert result.confidence == 0.0

    def test_info_severity_alias(self, scorer):
        result = scorer.score_from_finding(
            {"title": "Note", "description": "", "severity": "info"}
        )
        assert result.unknown is True
        assert result.score is None

    def test_inferred_scores_labeled(self, scorer):
        result = scorer.score_from_finding(
            {
                "title": "Remote Code Execution via SQLi",
                "description": "rce",
                "severity": "critical",
            }
        )
        assert result.inferred is True
        assert result.unknown is False
        assert result.score is not None and result.score >= 7.0

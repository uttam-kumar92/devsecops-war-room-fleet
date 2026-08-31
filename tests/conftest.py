from typing import Any, List
from unittest.mock import MagicMock
import pytest
from pydantic import BaseModel

import agents


class MockWeb(BaseModel):
    uri: str = "https://nvd.nist.gov/vuln/detail/CVE-2026-0001"
    title: str = "NVD Security Advisory CVE-2026-0001"


class MockGroundingChunk(BaseModel):
    web: MockWeb = MockWeb()


class MockGroundingMetadata(BaseModel):
    web_search_queries: List[str] = ["CVE SQL injection vulnerability patch"]
    grounding_chunks: List[MockGroundingChunk] = [MockGroundingChunk()]


class MockCandidate:
    def __init__(self):
        self.grounding_metadata = MockGroundingMetadata()
        self.content = MagicMock()
        mock_part = MagicMock()
        mock_part.text = "### 🛡️ Enterprise Threat Model & Security Audit Report\nMock remediation code patch content."
        self.content.parts = [mock_part]


class MockResponse:
    def __init__(self, text: str = "### 🛡️ Enterprise Threat Model & Security Audit Report\nMock remediation code patch content.", parsed: Any = None):
        self.text = text
        self.parsed = parsed
        self.candidates = [MockCandidate()]


@pytest.fixture
def mock_genai_client():
    """Fixture providing a mocked google.genai.Client instance."""
    client = MagicMock()
    client.models = MagicMock()

    def mock_generate_content(model: str, contents: Any, config: Any = None):
        if config and hasattr(config, "response_schema"):
            schema = getattr(config, "response_schema")
            if schema == agents.SecurityAuditPlan:
                return MockResponse(
                    text="{}",
                    parsed=agents.SecurityAuditPlan(
                        target_scope="Test Scope",
                        threat_vectors=["SQL Injection", "Command Injection"],
                        stride_focus=["Tampering", "Elevation of Privilege"],
                        milestones=[
                            agents.PlanMilestone(phase="Discovery", description="Test Threat Intel", assigned_agent="VulnerabilityScoutAgent")
                        ]
                    )
                )
            elif schema == agents.RedTeamCritique:
                return MockResponse(
                    text="{}",
                    parsed=agents.RedTeamCritique(
                        attack_simulated="SQLi Fuzzing",
                        bypass_possible=False,
                        fluff_detected=False,
                        unaddressed_risks=[],
                        recommendations_for_patch="Patch verified secure."
                    )
                )
            elif schema == agents.VerificationResult:
                return MockResponse(
                    text="{}",
                    parsed=agents.VerificationResult(
                        passed=True,
                        overall_security_score=10,
                        remediation_completeness_score=10,
                        estimated_cvss_score=8.5,
                        stride_scores=agents.STRIDEAssessment(
                            spoofing=7.0,
                            tampering=8.0,
                            repudiation=6.0,
                            information_disclosure=9.0,
                            denial_of_service=7.0,
                            elevation_of_privilege=8.5
                        ),
                        feedback="Remediation verified complete."
                    )
                )

        return MockResponse(text="### 🛡️ Enterprise Threat Model & Security Audit Report\nMock remediation code patch content.")

    client.models.generate_content.side_effect = mock_generate_content
    return client

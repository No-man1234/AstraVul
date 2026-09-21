"""
Strict Pydantic v2 schemas for Machine-Actionable Triage Reports.
Guarantees schema compliance and eliminates conversational hallucinations.
"""

from enum import Enum
from typing import List, Optional, Dict
from pydantic import BaseModel, Field


class ExploitabilityVerdict(str, Enum):
    CONFIRMED_EXPLOITABLE = "CONFIRMED_EXPLOITABLE"
    SUSPICIOUS_UNVERIFIED = "SUSPICIOUS_UNVERIFIED"
    BENIGN_FALSE_POSITIVE = "BENIGN_FALSE_POSITIVE"


class VulnerabilityTriageReport(BaseModel):
    """Deterministic security triage finding emitted per analyzed slice."""
    file_path: str = Field(description="Target source file path")
    slice_id: str = Field(description="Unique identifier of analyzed code slice")
    is_vulnerable: bool = Field(description="Binary classification verdict")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence score between 0.0 and 1.0")
    cwe_id: str = Field(description="Predicted Common Weakness Enumeration ID")
    cwe_name: str = Field(description="Human-readable name of the CWE")
    vulnerable_lines: List[int] = Field(description="Exact 1-indexed line numbers of the vulnerability")
    exploitability_verdict: ExploitabilityVerdict = Field(description="Triage assessment category")
    root_cause_analysis: str = Field(description="Detailed causal explanation of the security flaw")
    remediation_patch: Optional[str] = Field(default=None, description="Unified diff remediation guidance")
    token_usage: Dict[str, int] = Field(default_factory=dict, description="Token consumption breakdown")

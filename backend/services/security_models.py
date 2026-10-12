from dataclasses import dataclass, asdict

@dataclass
class VulnerabilityFinding:
    line: int
    severity: str
    type: str
    description: str
    recommendation: str
    owasp: str
    cwe: str
    file: str
    snippet: str = ""
    language: str = ""
    context: str = ""
    context_start: int = 0
    suggested_fix: str = ""
    fix_explanation: str = ""
    extra_steps: str = ""
    match_kind: str = "pattern_match"
    complete_fix: bool = False
    impact: str = ""
    classification: str = "potential"
    confidence: str = "low"
    line_end: int = 0
    redacted: bool = False

    def to_dict(self) -> dict:
        if not self.line_end:
            self.line_end = self.line
        return asdict(self)
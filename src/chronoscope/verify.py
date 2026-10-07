"""Case integrity verification: audit chain and evidence hashes."""

from __future__ import annotations

from dataclasses import dataclass, field

from chronoscope.audit import AuditLog, AuditVerification
from chronoscope.case import Case
from chronoscope.hashing import hash_file


@dataclass
class VerifyReport:
    audit: AuditVerification
    files_checked: int = 0
    evidence_problems: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.audit.ok and not self.evidence_problems


def verify_case(case: Case) -> VerifyReport:
    report = VerifyReport(AuditLog.verify(case.audit.path))
    for item in case.evidence_files():
        report.files_checked += 1
        where = f"[{item.label}] {item.location}"
        try:
            current = hash_file(item.location)
        except OSError as exc:
            report.evidence_problems.append(f"{where}: cannot read ({exc.strerror or exc})")
            continue
        if current.sha256 != item.sha256 or current.size != item.size:
            report.evidence_problems.append(
                f"{where}: SHA-256 {current.sha256} does not match recorded {item.sha256}"
            )
    return report

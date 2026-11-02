package securitygate

import rego.v1

valid_schema if {
	input.schema_version == "decision-input/v1"
}

valid_severity if {
	input.severity in {"low", "medium", "high", "critical"}
}

valid_category if {
	input.category in {"secret", "source", "dependency", "container", "runtime"}
}

valid_status if {
	input.status in {"confirmed", "suspected", "suppressed"}
}

valid_finding(finding) if {
	finding.schema_version == "evidence/v1"
	finding.finding_id != ""
	finding.fingerprint != ""
	finding.tool != ""
	finding.tool_version != ""
	valid_severity with input as finding
	valid_category with input as finding
	valid_status with input as finding
	finding.message != ""
	count(finding.requirement_ids) > 0
	finding.normalization_status == "complete"
	finding.observed_at != ""
}

valid_suppression(finding) if {
	finding.status == "suppressed"
	finding.suppression.reason != ""
	finding.suppression.reference != ""
	finding.suppression.expires_at != ""
}

document_is_complete(document) if {
	document.schema_version == "evidence-document/v1"
	document.gate.gate_id != ""
	document.gate.required == true
	document.gate.completed == true
	document.gate.tool_exit_code in {0, 1}
	document.normalization.status == "complete"
	count(document.normalization.raw_artifacts) > 0
}

completed_required_gate(gate_id) if {
	some document in input.evidence_documents
	document.gate.gate_id == gate_id
	document_is_complete(document)
}

missing_required_gates contains gate_id if {
	gate_id := input.thresholds.required_gates[_]
	not completed_required_gate(gate_id)
}

invalid_documents contains gate_id if {
	some document in input.evidence_documents
	gate_id := document.gate.gate_id
	gate_id != ""
	not document_is_complete(document)
}

all_findings contains finding if {
	some document in input.evidence_documents
	finding := document.findings[_]
}

valid_actionable_finding(finding) if {
	valid_finding(finding)
	finding.status == "confirmed"
}

invalid_findings contains finding_id if {
	some document in input.evidence_documents
	finding := document.findings[_]
	not valid_finding(finding)
	finding_id := object.get(finding, "finding_id", "unknown-finding")
}

invalid_suppressions contains finding_id if {
	some document in input.evidence_documents
	finding := document.findings[_]
	finding.status == "suppressed"
	not valid_suppression(finding)
	finding_id := object.get(finding, "finding_id", "unknown-finding")
}

blocking_findings contains finding if {
	finding := all_findings[_]
	valid_actionable_finding(finding)
	finding.severity in input.thresholds.blocking_severities
}

warning_findings contains finding if {
	finding := all_findings[_]
	valid_actionable_finding(finding)
	finding.severity in input.thresholds.warning_severities
}

schema_is_invalid if {
	not valid_schema
}

has_block if {
	schema_is_invalid
}

has_block if {
	count(missing_required_gates) > 0
}

has_block if {
	count(invalid_documents) > 0
}

has_block if {
	count(invalid_findings) > 0
}

has_block if {
	count(invalid_suppressions) > 0
}

has_block if {
	count(blocking_findings) > 0
}

has_warning if {
	not has_block
	count(warning_findings) > 0
}

decision := "BLOCK" if has_block

decision := "WARN" if has_warning

decision := "PASS" if {
	not has_block
	not has_warning
}

reason_for_finding(finding) := {
	"gate_id": gate_id,
	"finding_id": finding.finding_id,
	"severity": finding.severity,
	"requirement_ids": finding.requirement_ids,
	"message": finding.message,
} if {
	some document in input.evidence_documents
	finding in document.findings
	gate_id := document.gate.gate_id
}

reasons contains reason if {
	finding := blocking_findings[_]
	reason := reason_for_finding(finding)
}

reasons contains reason if {
	finding := warning_findings[_]
	reason := reason_for_finding(finding)
}

reasons contains {
	"gate_id": "policy-input",
	"message": "Decision input does not match schema decision-input/v1.",
} if {
	schema_is_invalid
}

reasons contains {
	"gate_id": gate_id,
	"message": "Required security gate did not produce complete evidence.",
} if {
	gate_id := missing_required_gates[_]
}

reasons contains {
	"gate_id": gate_id,
	"message": "Security gate evidence is incomplete or invalid.",
} if {
	gate_id := invalid_documents[_]
}

reasons contains {
	"gate_id": "evidence",
	"finding_id": finding_id,
	"message": "Finding evidence is incomplete or unsupported.",
} if {
	finding_id := invalid_findings[_]
}

reasons contains {
	"gate_id": "evidence",
	"finding_id": finding_id,
	"message": "Suppressed finding is missing valid suppression metadata.",
} if {
	finding_id := invalid_suppressions[_]
}

deployment_allowed if {
	decision != "BLOCK"
}

deployment_allowed := false if {
	decision == "BLOCK"
}

decision_record := {
	"schema_version": "decision/v1",
	"policy_version": input.policy_version,
	"run": input.run,
	"decision": decision,
	"deployment_allowed": deployment_allowed,
	"reasons": [reason | reasons[reason]],
	"completed_gates": [gate_id | gate_id := input.thresholds.required_gates[_]; completed_required_gate(gate_id)],
	"missing_required_gates": [gate_id | gate_id := missing_required_gates[_]],
}

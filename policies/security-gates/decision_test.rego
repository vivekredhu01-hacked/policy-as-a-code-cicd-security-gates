package securitygate

import rego.v1

base_input := {
	"schema_version": "decision-input/v1",
	"policy_version": "0.1.0",
	"run": {
		"run_id": "test-run",
		"fixture_id": "F06",
		"commit_id": "test-commit",
		"pipeline": "proposed",
		"stage": "source",
	},
	"thresholds": {
		"blocking_severities": ["medium", "high", "critical"],
		"warning_severities": ["low"],
		"required_gates": ["secret-detection"],
	},
	"evidence_documents": [{
		"schema_version": "evidence-document/v1",
		"gate": {
			"gate_id": "secret-detection",
			"required": true,
			"completed": true,
			"tool_exit_code": 0,
		},
		"findings": [],
		"normalization": {
			"status": "complete",
			"raw_artifacts": ["artifacts/report.json"],
		},
	}],
}

make_finding(severity) := {
	"schema_version": "evidence/v1",
	"finding_id": "test:finding",
	"fingerprint": "sha256:test",
	"tool": "semgrep",
	"tool_version": "1.0.0",
	"category": "source",
	"severity": severity,
	"confidence": "high",
	"message": "Test finding",
	"requirement_ids": ["SSDF-PW.5", "ASVS-V5"],
	"asset": {"path": "src/example.js", "line_start": 1, "line_end": 1},
	"status": "confirmed",
	"normalization_status": "complete",
	"observed_at": "2026-10-28T00:00:00Z",
}

with_finding(base, severity) := object.union(base, {"evidence_documents": [{
	"schema_version": "evidence-document/v1",
	"gate": {
		"gate_id": "secret-detection",
		"required": true,
		"completed": true,
		"tool_exit_code": 0,
	},
	"findings": [make_finding(severity)],
	"normalization": {
		"status": "complete",
		"raw_artifacts": ["artifacts/report.json"],
	},
}]})

with_findings(base, findings) := object.union(base, {"evidence_documents": [object.union(base.evidence_documents[0], {"findings": findings})]})

test_clean_input_passes if {
	decision == "PASS" with input as base_input
}

test_low_finding_warns if {
	decision == "WARN" with input as with_finding(base_input, "low")
}

test_medium_finding_blocks if {
	decision == "BLOCK" with input as with_finding(base_input, "medium")
}

test_findings_exit_code_is_complete_evidence if {
	document := object.union(base_input.evidence_documents[0], {
		"gate": object.union(base_input.evidence_documents[0].gate, {"tool_exit_code": 1}),
		"findings": [make_finding("high")],
	})
	candidate := object.union(base_input, {"evidence_documents": [document]})
	decision == "BLOCK" with input as candidate
}

test_high_finding_blocks if {
	decision == "BLOCK" with input as with_finding(base_input, "high")
}

test_critical_finding_blocks if {
	decision == "BLOCK" with input as with_finding(base_input, "critical")
}

test_block_takes_precedence_over_warning if {
	candidate := with_findings(base_input, [make_finding("medium"), make_finding("low")])
	decision == "BLOCK" with input as candidate
}

test_failed_required_gate_blocks if {
	candidate := object.union(base_input, {"evidence_documents": [{
		"schema_version": "evidence-document/v1",
		"gate": {
			"gate_id": "secret-detection",
			"required": true,
			"completed": false,
			"tool_exit_code": 1,
		},
		"findings": [],
		"normalization": {
			"status": "complete",
			"raw_artifacts": ["artifacts/report.json"],
		},
	}]})
	decision == "BLOCK" with input as candidate
}

test_missing_required_gate_blocks if {
	candidate := object.union(base_input, {"evidence_documents": []})
	decision == "BLOCK" with input as candidate
}

test_invalid_schema_blocks if {
	candidate := object.union(base_input, {"schema_version": "decision-input/v0"})
	decision == "BLOCK" with input as candidate
}

test_invalid_finding_blocks if {
	candidate := with_findings(base_input, [object.union(make_finding("medium"), {"normalization_status": "partial"})])
	decision == "BLOCK" with input as candidate
}

test_invalid_suppression_blocks if {
	candidate := with_findings(base_input, [object.union(make_finding("low"), {"status": "suppressed"})])
	decision == "BLOCK" with input as candidate
}

test_valid_suppression_does_not_block if {
	candidate := with_findings(base_input, [object.union(make_finding("low"), {
		"status": "suppressed",
		"suppression": {
			"reason": "Accepted test exception",
			"reference": "EX-001",
			"expires_at": "2099-12-31T00:00:00Z",
		},
	})])
	decision == "PASS" with input as candidate
}

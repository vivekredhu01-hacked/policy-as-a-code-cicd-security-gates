# Project Scope

## Title
Policy-as-Code Security Gates for CI/CD Pipelines: Operationalising NIST SSDF
and OWASP ASVS for Early Vulnerability Detection

## Project Objective
This project aims to design, implement, and evaluate a Policy-as-Code
security-gate framework for CI/CD pipelines. The framework will translate
selected NIST SSDF and OWASP ASVS requirements into machine-enforceable
policies, aggregate evidence from open-source security tools, and produce
PASS/WARN/BLOCK decisions for controlled vulnerable commits.

## Problem Statement
Modern CI/CD pipelines often run security scanners as independent tasks with
tool-specific outputs and thresholds. They do not necessarily provide
traceability from secure-development requirements to machine-enforceable
decisions, nor evidence that a finding was detected early enough to prevent a
vulnerable deployment. This project evaluates whether a central
policy-as-code decision layer can close that gap while maintaining acceptable
pipeline overhead.

## Scope
The PoC includes:
- GitHub Actions as the primary CI/CD platform
- OPA/Rego as the central policy decision language
- Open-source secret, SAST, SCA, container, and DAST tools
- Selected NIST SSDF and OWASP ASVS requirements
- Controlled commits with known vulnerability ground truth
- Baseline versus proposed-pipeline comparison
- Kubernetes admission control as supporting deployment-time evidence

## Out of Scope
The PoC does not include:
- Terraform, Dockerfiles, Helm charts, or SBOM validation
- Runtime monitoring or drift detection
- Secrets scanning
- Container image vulnerability scanning
- SIEM, SOAR, or external governance platforms
- Full regulatory compliance mapping to ISO 27001, GDPR, or PCI-DSS
- Multi-cloud or production-grade deployment
- Enterprise-scale policy lifecycle management

## Enforcement Points
The PoC implements enforcement at two points:
1. Staged CI/CD security gates using GitHub Actions and scanner evidence
2. Central PASS/WARN/BLOCK decisions using OPA/Rego
3. Kubernetes admission control as a supporting defence-in-depth enforcement point

## Research Objective Alignment
This PoC supports:
- problem interpretation and literature-based requirement selection
- design of a traceable security-gate framework
- implementation of the policy decision layer
- controlled comparative experimental evaluation
- critical analysis of detection, prevention, false positives, and overhead

## Expected Contribution
The PoC is expected to contribute:
- a reproducible policy-as-code security-gate framework
- a traceability mapping from NIST SSDF and OWASP ASVS to gate policies
- a common evidence and decision model across heterogeneous scanners
- controlled evidence on early detection, deployment prevention, false positives,
  and CI/CD overhead

## Success Criteria
The PoC is considered successful if:
- all selected policies are implemented and versioned
- compliant manifests pass CI and admission control
- non-compliant manifests are blocked in CI
- non-compliant manifests are rejected at admission when applied directly
- results are collected for all scenarios
- baseline and PoC behavior can be compared
- policy checks introduce acceptable overhead for the PoC context

## Main Research Question
To what extent can an SSDLC-derived policy-as-code security gate framework
improve early vulnerability detection and prevent vulnerable deployments in
CI/CD pipelines compared with a traditional late-stage security approach,
while maintaining acceptable pipeline overhead?

## Supporting Research Questions
RQ1: How can selected NIST SSDF and OWASP ASVS requirements be translated into
machine-enforceable security-gate policies within GitHub Actions?

RQ2: How does the proposed framework affect vulnerability detection rate,
stage of first detection, time-to-security-feedback, and vulnerable
deployments prevented?

RQ3: What CI/CD overhead and false-positive cost are introduced by the
proposed security gates?
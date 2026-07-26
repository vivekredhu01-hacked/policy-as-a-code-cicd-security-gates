# Reusing Policy-as-Code Across CI/CD and Kubernetes Admission Control

[![Paper](https://img.shields.io/badge/Paper-MDPI%20Computers-blue)](https://www.mdpi.com/2073-431X/15/7/453)
[![DOI](https://img.shields.io/badge/DOI-10.3390/computers15070453-blue)](https://doi.org/10.3390/computers15070453)

This repository contains the **official replication package** accompanying the paper:

> **Reusing Policy-as-Code Across CI/CD and Kubernetes Admission Control: An Empirical Assessment of Governance Consistency**  
> **Luís Nogueira** and **Alice Resende**  
> *Computers*, **2026**, 15(7), 453  
> https://doi.org/10.3390/computers15070453

The repository provides all artefacts required to reproduce the experimental evaluation presented in the paper, including reusable Policy-as-Code definitions, Kubernetes manifests, admission-control configurations, Continuous Integration workflows, experimental scenarios, automation scripts, and validation results.

---

# Overview

Policy-as-Code (PaC) has become an important approach for automating governance, security, and compliance throughout cloud-native software delivery pipelines. However, equivalent governance policies are frequently implemented independently across multiple validation stages, increasing maintenance effort and creating opportunities for policy drift.

This work investigates whether a **shared policy-definition layer** can be reused consistently across complementary enforcement stages while preserving governance enforcement throughout the software delivery lifecycle.

The proposed reusable multi-stage Policy-as-Code enforcement model evaluates identical Rego policy definitions during:

- Continuous Integration (CI) validation using **Conftest**
- Kubernetes admission control using **OPA Gatekeeper**

Rather than introducing a new policy language, policy engine, or enforcement framework, the study empirically evaluates the practical feasibility of policy reuse across complementary enforcement stages.

The experimental evaluation investigates:

- automatic detection of insecure Kubernetes configurations;
- governance assurance through multi-stage enforcement;
- mitigation of CI bypass scenarios through deployment-time admission control.

---

# Repository Highlights

- Official replication package accompanying the published paper
- Shared Policy-as-Code definition layer
- 29 Kubernetes manifests
- 37 experimental scenarios
- 8 Kubernetes resource types
- 5 governance policies
- 9 reusable Rego `deny` rules
- 261 policy assertions
- GitHub Actions CI workflows
- OPA Gatekeeper admission-control configuration
- Complete experimental results

---

# Repository Structure

```text
.
├── docs/                      # Supporting documentation
├── gatekeeper/                # ConstraintTemplates and Constraints
├── policies/
│   └── kubernetes/            # Shared Rego policy definitions
├── results/                   # Experimental outputs
├── scripts/                   # Automation scripts
├── tests/                     # Kubernetes manifests and scenarios
├── .github/
│   └── workflows/             # GitHub Actions workflows
└── README.md
```

## Directory Description

| Directory | Description |
|------------|-------------|
| `docs/` | Documentation describing the experimental artefacts and evaluation process. |
| `gatekeeper/` | OPA Gatekeeper ConstraintTemplates and Constraints used during deployment-time validation. |
| `policies/kubernetes/` | Shared Rego policy-definition layer reused across all enforcement stages. |
| `results/` | Experimental outputs and validation results. |
| `scripts/` | Helper scripts for executing experiments and collecting results. |
| `tests/` | Kubernetes manifests covering compliant workloads, policy violations, and CI bypass scenarios. |
| `.github/workflows/` | GitHub Actions workflows implementing Continuous Integration validation. |

Together, these artefacts enable complete reproduction of the experimental evaluation presented in the paper.

---

# Experimental Workflow

```text
Evaluation Dataset
        │
        ▼
Shared Policy-Definition Layer (Rego)
        │
        ├──────────────┐
        ▼              ▼
CI Validation      Admission Control
(Conftest)         (OPA Gatekeeper)
        │              │
        └──────┬───────┘
               ▼
Experimental Results
               ▼
Evaluation Metrics
               ▼
Research Questions
```

The same Rego policy definitions are reused throughout the evaluation. Consequently, any observed differences arise from the execution context rather than from differences in policy implementation.

---

# Experimental Dataset

| Item | Value |
|------|------:|
| Kubernetes manifests | 29 |
| Experimental scenarios | 37 |
| Kubernetes resource types | 8 |
| Governance policies | 5 |
| Rego `deny` rules | 9 |
| Policy assertions | 261 |

The dataset includes:

- compliant workloads;
- negative-control resources;
- single-policy violations;
- multi-policy violations;
- CI bypass scenarios.

Every experimental scenario specifies its expected outcome *a priori*, enabling objective and reproducible evaluation of policy behaviour.

---

# Governance Policies

| Policy | Description | CI | Admission Control |
|---------|-------------|:--:|:----------------:|
| P1 | No Root Execution | ✓ | ✓ |
| P2 | No Privilege Escalation | ✓ | ✓ |
| P3 | Resource Requests and Limits Required | ✓ | – |
| P4 | No Mutable Image Tags (`latest`) | ✓ | ✓ |
| P5 | No Privileged Containers | ✓ | – |

The policies implemented exclusively during Continuous Integration reflect the implementation scope adopted for the evaluated proof-of-concept rather than limitations of OPA Gatekeeper or of the proposed architectural model.

---

# Reproducing the Evaluation

## 1. Continuous Integration Validation

```bash
conftest test tests/
```

---

## 2. Deploy OPA Gatekeeper

```bash
kubectl apply -f gatekeeper/
```

---

## 3. Execute Admission-Control Validation

Submit the Kubernetes manifests contained in `tests/` to the cluster.

Admission decisions are evaluated through Kubernetes validating admission webhooks using the same governance requirements implemented in the shared Rego policy-definition layer.

---

## 4. Compare Results

Compare the observed policy decisions with the expected outcomes provided in the experimental scenarios.

The evaluation metrics reported in the paper (Detection Rate, False Positive Rate, False Negative Rate, Policy Coverage, and CI Bypass Protection) can then be reproduced.

---

# Research Questions

The experimental evaluation addresses the following research questions.

### RQ1

Can reusable Policy-as-Code definitions accurately detect insecure Kubernetes configurations automatically?

### RQ2

Can reusable Policy-as-Code definitions be enforced consistently across Continuous Integration validation and Kubernetes admission control?

### RQ3

Can Kubernetes admission control mitigate governance failures caused by CI bypass scenarios?

---

# Replication Artefacts

The repository includes:

- reusable Rego policy definitions;
- Kubernetes evaluation manifests;
- GitHub Actions workflows;
- OPA Gatekeeper ConstraintTemplates and Constraints;
- experimental scenarios;
- automation scripts;
- validation outputs;
- supporting documentation.

Together, these artefacts enable independent reproduction of all experiments and verification of the empirical results reported in the accompanying paper.

---

# Citation

If you use this repository in your research, please cite:

```bibtex
@Article{computers15070453,
  AUTHOR  = {Nogueira, Luís and Resende, Alice},
  TITLE   = {Reusing Policy-as-Code Across CI/CD and Kubernetes Admission Control: An Empirical Assessment of Governance Consistency},
  JOURNAL = {Computers},
  YEAR    = {2026},
  VOLUME  = {15},
  NUMBER  = {7},
  ARTICLE-NUMBER = {453},
  DOI     = {10.3390/computers15070453}
}
```

---

# License

This repository is distributed under the **MIT License**.

If you use this replication package in academic work, please cite the accompanying paper.
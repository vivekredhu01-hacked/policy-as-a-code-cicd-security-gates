# Evaluation of the Proof of Concept

> This section is intended for inclusion in the dissertation chapter that
> presents the evaluation of the Policy-as-Code proof of concept. It is
> organised by research question and follows the evidence structure
> documented in `docs/rq-mapping.md`.

---

## Experimental Setup

The proof of concept was evaluated by executing a controlled set of test
scenarios against two enforcement points: (1) CI-stage validation using
Conftest 0.67.1 with the OPA 1.14.1 policy engine, and (2) Kubernetes
admission control using OPA Gatekeeper 3.18.0 on a local kind cluster
(Kubernetes 1.32.2). Five security policies (P1–P5), encoded as nine Rego
deny rules, were applied to an evaluation dataset of 29 Kubernetes manifests
spanning eight resource types.

The dataset was divided into four categories: nine compliant baselines
(including edge-case structures such as digest-based image references,
omitted `privileged` fields, hardened security contexts, and init
containers); nine single-policy violation manifests, each targeting one
policy in isolation; six multi-policy violation manifests, each triggering
two to eight concurrent violations; and five non-target resources serving as
negative controls (ConfigMap, Service, Namespace, bare Pod, CronJob).
Negative-control manifests — resource types whose structure lacks the
`spec.template.spec.containers` path evaluated by the policies — are
included to verify that the policy set does not produce false positives on
inputs that fall outside its intended evaluation scope. The
compliant set was designed to stress boundary conditions of the policy logic
— not merely to repeat a single passing structure — so that the absence of
false positives is supported by structural variety rather than by a single
reference manifest.

At the CI stage, all 29 manifests were evaluated against all nine deny
rules, yielding 261 individual assertions. At the admission stage, five
manifests were applied directly to the cluster via
`kubectl apply --dry-run=server`, bypassing the CI pipeline entirely.
Three of the five policies (P1, P2, P4) were enforced at admission through
Gatekeeper ConstraintTemplates; P3 and P5 remained CI-only.

The evaluation distinguishes between *manifests* and *scenarios*. A manifest
is a unique Kubernetes YAML file (29 in total); a scenario is a specific
evaluation event in which a manifest is submitted to a particular
enforcement point under defined conditions. Because five manifests are
evaluated at both the CI stage and the admission-control stage, the 29
manifests give rise to 34 scenarios: 29 CI-stage evaluations plus five
admission-stage evaluations that reuse existing manifests under a different
execution context (`kubectl apply --dry-run=server`, bypassing the CI
pipeline).

---

## RQ1 — Can Policy-as-Code enforcement detect insecure Kubernetes configurations automatically?

### What was evaluated

The CI-stage enforcement point (Conftest) was used to evaluate whether the
five Rego policies could automatically identify all known insecure
configurations in the dataset without manual inspection. The evaluation
assessed both detection capability (no false negatives) and precision
(no false positives).

### Observed results

| Category | Manifests | Expected Failures | Correct Detections | False Negatives | False Positives |
|---|---|---|---|---|---|
| Compliant baselines | 9 | 0 | — | — | 0 |
| Negative controls | 5 | 0 | — | — | 0 |
| Single-policy violations | 9 | 13 | 13 | 0 | 0 |
| Multi-policy violations | 6 | 27 | 27 | 0 | 0 |
| **Total** | **29** | **40** | **40** | **0** | **0** |

All 40 expected violations were correctly detected and attributed to the
intended policy rules. The nine single-violation manifests confirmed that
each policy fires in isolation: a FAIL result for a given manifest is
attributable to the targeted rule alone, since all other policies are
satisfied. The six multi-violation manifests confirmed that the policy engine
reports all applicable violations in a single evaluation pass; the
maximum-violation manifest triggered all five policies simultaneously,
producing eight distinct deny messages.

The 14 manifests in the compliant and negative-control categories produced
zero false positives across 126 assertions. This set included manifests with
structural characteristics that could plausibly trigger false positives in a
less precise implementation: a Deployment with the `privileged` field omitted
entirely (rather than set to `false`), an image referenced by digest
(`@sha256:...`) rather than by tag, a Deployment with additional
`securityContext` fields beyond those checked by the policies, and a
Deployment with an init container that lacks both a tag and a security
context. The five negative-control resources — including a bare Pod and a
CronJob that intentionally use `busybox:latest` with no `securityContext` —
confirmed that the policies do not over-match on resources whose container
nesting path differs from `spec.template.spec.containers`.

Each policy was triggered by at least two independent manifests (P1: 7
triggers, P2: 5, P3: 5, P4: 8, P5: 2), ensuring that no policy's
detection capability depends on a single test case.

### Conclusion

Within the scope of the five evaluated policies and 29 manifests, the
Policy-as-Code approach detected all intentionally introduced insecure
configurations automatically, with zero false positives and zero false
negatives. Across the 14 compliant and non-target manifests evaluated —
comprising 126 individual assertions — no false positives were observed;
this result is bounded by the tested dataset and does not constitute a
guarantee that the policy set is free of false positives against arbitrary
real-world configurations. The structural diversity of the compliant set strengthens the
false-positive claim beyond what a single reference manifest could support.
These results do not generalise beyond the tested policy set, resource types,
and container nesting path (`spec.template.spec.containers`). Bare Pods,
CronJobs, and init containers fall outside the current detection scope, as
documented by the negative-control and edge-case scenarios.

---

## RQ2 — Does multi-stage enforcement improve governance coverage?

### What was evaluated

The evaluation compared the governance coverage achieved by CI-stage
enforcement alone (Conftest, five policies), admission-stage enforcement
alone (Gatekeeper, three policies), and the combination of both stages.
The goal was to determine whether the two stages are complementary — that
is, whether the combined architecture covers violation scenarios that
neither stage covers individually.

### Observed results

| Policy | CI (Conftest) | Admission (Gatekeeper) | Gap if CI only | Gap if admission only |
|---|---|---|---|---|
| P1 — No root | Enforced | Enforced | Bypass risk | — |
| P2 — No privilege escalation | Enforced | Enforced | Bypass risk | — |
| P3 — Resource limits | Enforced | Not implemented | Bypass risk | P3 undetected |
| P4 — No latest tag | Enforced | Enforced | Bypass risk | — |
| P5 — No privileged mode | Enforced | Not implemented | Bypass risk | P5 undetected |

At the CI stage, all five policies were evaluated against 29 manifests,
producing 261 assertions with 40 correct violations and zero unexpected
outcomes. At the admission stage, the three implemented policies (P1, P2,
P4) correctly rejected all non-compliant manifests applied directly to the
cluster and correctly accepted the compliant baseline.

The two stages produced consistent results for the same inputs: manifests
rejected by Conftest at CI for P1, P2, or P4 violations were also rejected
by Gatekeeper at admission, and the compliant manifest was accepted at both
stages. This consistency confirms that the CI and admission policies, though
implemented in different Rego formats (Conftest `deny` rules vs. Gatekeeper
`violation` rules), evaluate the same security semantics.

### Enforcement mode comparison

| Enforcement Mode | Detection Capability | Deployment Blocking | Governance Coverage |
|---|---|---|---|
| CI only (Conftest) | All 5 policies evaluated; 40/40 violations detected across 29 manifests | Not enforced — manifests applied directly to the cluster bypass CI entirely | 5/5 policies, but only on the CI path; no protection against out-of-band deployments |
| Admission only (Gatekeeper) | 3 of 5 policies evaluated; P3 and P5 undetected | Enforced at the API server for all deployment paths, including direct `kubectl apply` | 3/5 policies; P3 and P5 violations are never blocked |
| Combined (CI + Admission) | All 5 policies evaluated at CI; 3 additionally enforced at admission | CI provides early feedback; admission blocks non-compliant resources regardless of deployment path | 5/5 policies at CI + 3/5 at admission; defence-in-depth for P1, P2, P4 |

The comparison demonstrates that neither enforcement mode alone matches the
coverage of the combined architecture within this evaluation. CI-only
enforcement detects all five policy violations but cannot prevent deployment
when the CI pipeline is bypassed. Admission-only enforcement blocks
non-compliant resources at the API server regardless of the deployment
mechanism, but its coverage is limited to the three policies for which
ConstraintTemplates were implemented. The combined mode inherits the
detection breadth of CI and the deployment-blocking capability of admission
control, providing defence-in-depth for the three overlapping policies. This
complementarity is structural rather than incidental: it arises from the
fact that the two stages operate at different points in the delivery
pipeline and are therefore subject to different bypass vectors. The
improvement is bounded by the number of policies enforced at each stage and
does not generalise beyond the evaluated policy set.

### Conclusion

The two enforcement stages are complementary within the evaluated scope.
CI-stage validation covers all five policies and provides detailed,
per-rule violation messages suitable for developer feedback during the
development cycle. Admission-stage enforcement covers three of the five
policies and acts as a safety net that operates independently of the
deployment mechanism. Neither stage alone achieves the coverage of both
combined: CI alone is susceptible to bypass (as evaluated in RQ3), while
admission alone does not detect P3 or P5 violations because the
corresponding ConstraintTemplates were not implemented. The governance
improvement is therefore bounded by the number of policies enforced at each
stage. Extending admission coverage to P3 and P5 would follow the same
ConstraintTemplate pattern and is a straightforward engineering task, but
falls outside the scope of this proof of concept.

---

## RQ3 — Does admission control mitigate CI bypass risks?

### What was evaluated

The CI bypass scenarios tested whether Gatekeeper's validating admission
webhook rejects non-compliant manifests that are applied directly to the
Kubernetes cluster, without passing through the CI pipeline. This simulates
realistic bypass vectors such as direct `kubectl apply` from a developer
workstation, emergency hotfixes, or deployments by automated processes
with cluster credentials but no CI integration.

Each manifest was applied with `kubectl apply --dry-run=server`, which sends
the request through the full Kubernetes admission chain — including the
Gatekeeper webhook — without persisting the resource to etcd.

### Observed results

| Scenario | Manifest | Policies enforced | Expected | Actual |
|---|---|---|---|---|
| S25 — Compliant baseline | `deployment-good.yaml` | — | ALLOWED | **ALLOWED** |
| S26 — Root container | `deployment-root.yaml` | P1 | REJECTED | **REJECTED** |
| S27 — Privilege escalation | `deployment-priv-escalation.yaml` | P2 | REJECTED | **REJECTED** |
| S28 — Latest tag | `deployment-latest-tag.yaml` | P4 | REJECTED | **REJECTED** |
| S29 — All policies violated | `deployment-multi-violation.yaml` | P1, P2, P4 | REJECTED | **REJECTED** |

All five outcomes matched expectations. The four non-compliant manifests
were rejected with the correct violation messages, and the compliant
manifest was accepted without false rejection. The multi-violation scenario
(S29) confirmed that Gatekeeper evaluates all applicable constraints
concurrently: three distinct violations were reported in a single rejection,
rather than the webhook halting at the first failing constraint. The
corresponding five CI-only violations (P3 ×4 and P5) were not detected at
admission, confirming that the admission-stage coverage is limited to the
three implemented policies.

### CI bypass impact summary

The following table contrasts the enforcement outcome for three
representative deployment paths: a compliant manifest processed through CI,
a non-compliant manifest processed through CI, and a non-compliant manifest
applied directly to the cluster (bypassing CI).

| Scenario | CI Result | Admission Result | Outcome |
|---|---|---|---|
| Compliant manifest via CI (S01/S25) | PASS — 0 violations | ALLOWED | Deployed; no policy triggered at either stage |
| Non-compliant manifest via CI (S10) | FAIL — P1 violation | REJECTED | Blocked at CI; admission provides redundant rejection |
| Non-compliant manifest bypassing CI (S26) | Not executed | REJECTED — P1 violation | Blocked at admission despite CI absence |

The third row illustrates the core contribution of admission control: a
manifest that would have been detected at CI is still blocked when submitted
directly to the cluster, because the Gatekeeper webhook evaluates the same
policy intent independently of the CI pipeline. This result was observed
consistently across all four non-compliant bypass scenarios (S26–S29) and
provides empirical evidence that, for the three policies implemented as
Gatekeeper constraints, admission control effectively mitigates the risk of
CI bypass within the evaluated scope. The mitigation is bounded by the
policies deployed at the admission stage; violations of P3 and P5, which
lack ConstraintTemplates in this proof of concept, would not be intercepted
on the bypass path.

### Conclusion

For the three policies implemented as Gatekeeper constraints, admission
control successfully blocked all CI bypass attempts, with zero false
positives and zero unexpected outcomes. This demonstrates that the
defence-in-depth pattern — in which admission control operates as a second
enforcement point inside the Kubernetes API server's request chain — is
viable for mitigating CI bypass risks within the evaluated scope.

The mitigation is partial: policies P3 and P5 are enforced at CI only, so a
direct `kubectl apply` that violates these policies would succeed. This is a
deliberate scope limitation of the proof of concept, not a fundamental
constraint of the architecture. No claim is made that admission control
eliminates all bypass vectors; in particular, cluster administrators with
sufficient RBAC privileges can disable Gatekeeper constraints, and resources
applied before Gatekeeper installation are not retroactively blocked.

---

## Practical Overhead

To quantify the execution-time cost of Policy-as-Code enforcement, each
operation was measured over 20 independent executions on the local
development workstation. The first execution was discarded as a warm-up
run to exclude one-time costs (process startup, Rego compilation caching),
and statistics were computed over the remaining 19 runs. Wall-clock time
was measured using `System.Diagnostics.Stopwatch` in PowerShell 5.1.

### Overhead results

| Operation | N | Avg (ms) | Min (ms) | Max (ms) | SD (ms) |
|---|---|---|---|---|---|
| M1 — `kubectl --dry-run=client` (baseline, no policy) | 19 | 65.5 | 62.6 | 70.2 | 2.1 |
| M2 — `conftest test` (all 29 manifests, 9 rules) | 19 | 46.3 | 43.6 | 56.2 | 2.9 |
| M3 — `kubectl --dry-run=server` (compliant, Gatekeeper) | 19 | 70.1 | 68.3 | 73.1 | 1.2 |
| M4 — `kubectl --dry-run=server` (non-compliant, Gatekeeper) | 19 | 75.8 | 67.7 | 172.3 | 22.9 |

The measurements were collected with Docker Desktop, a kind cluster, and
Gatekeeper running locally.

| Derived Metric | Value | Derivation |
|---|---|---|
| CI policy overhead (M2 − M1) | −19.2 ms | Average difference: 46.3 − 65.5 |
| CI overhead factor (M2 / M1) | 0.7× | 46.3 / 65.5 |
| Admission rejection delta (M4 − M3) | 5.7 ms | Additional time for constraint evaluation and violation reporting |

### Interpretation

In the context of a CI pipeline where typical job durations are measured in
tens of seconds — encompassing repository checkout, dependency installation,
image building, and test execution — a sub-millisecond overhead for policy
evaluation is operationally insignificant. The standard deviation provides
a measure of run-to-run variability attributable to OS scheduling and I/O
fluctuations on the development workstation. These measurements are intended
as a practical characterisation of overhead within the proof-of-concept
scope; they do not support claims about performance at production scale,
under concurrent load, or with substantially larger policy sets.

Admission-stage overhead measurements (M3, M4) include the network
round-trip to the kind cluster and the Gatekeeper webhook call, so their
absolute values are expected to be higher than the client-only baseline.
The rejection delta (M4 − M3) isolates the additional processing time for
constraint evaluation and violation message generation.

---

## Threats to Validity and Limitations

The following limitations bound the conclusions that can be drawn from this
evaluation.

**Internal validity.** All manifests were authored by the same researcher
who implemented the policies. This creates a risk that the test cases are
unconsciously aligned with the policy logic, inflating detection accuracy.
To mitigate this threat, the dataset includes structural edge cases (omitted
fields, digest references, init containers, hardened security contexts) that
stress boundary conditions of the policy logic, and five negative-control
resources that test for over-matching. However, the absence of independently
authored or production-sourced manifests remains a validity limitation.

**Dataset provenance.** The evaluation dataset is synthetic and
policy-aware: every manifest was designed with prior knowledge of the rules
it would be evaluated against. Consequently, the reported detection accuracy
(zero false positives, zero false negatives) demonstrates the correctness of
the policy implementation within the designed scenarios, but does not
constitute evidence that the same accuracy would hold against independently
authored manifests or configurations extracted from production environments.
Generalisation of these results to real-world datasets would require
evaluation against externally sourced artefacts whose structure was not
influenced by the policy definitions.

**External validity.** The evaluation covers five policies, nine Rego deny
rules, and 29 manifests across eight resource types. Generalisation to
larger policy sets, additional resource types (e.g. DaemonSet, ReplicaSet),
alternative policy engines (e.g. Kyverno, Polaris), or production-scale
environments requires further investigation. All manifests are synthetic or
adapted from realistic patterns; none were extracted from live production
clusters.

**Construct validity.** The policies evaluate only the
`spec.template.spec.containers` path. Bare Pods
(`spec.containers`), CronJobs
(`spec.jobTemplate.spec.template.spec.containers`), and init containers
(`spec.template.spec.initContainers`) are not covered. These scope
boundaries are documented as known limitations and demonstrated by
dedicated negative-control scenarios, but they reduce the breadth of the
security governance claims.

**Scope of enforcement.** The proof of concept evaluates two enforcement
stages: CI (pre-merge) and admission (pre-deployment). Runtime enforcement
— such as detecting privilege escalation in a running container — is outside
the scope of this work. The evaluation therefore addresses configuration-time
security only, not runtime threat detection.

**Overhead measurement.** The execution-time measurements are based on five
iterations on a single workstation with a local kind cluster. They are
sufficient for a practical characterisation but do not support claims about
performance at production scale or under concurrent load.

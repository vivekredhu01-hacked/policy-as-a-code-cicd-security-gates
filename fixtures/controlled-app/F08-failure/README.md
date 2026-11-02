# F08 scanner-failure fixture

This fixture represents a required source-analysis scanner that failed before
producing complete evidence. The decision policy must fail closed with
`BLOCK`; it must not treat the absence of findings as `PASS`.

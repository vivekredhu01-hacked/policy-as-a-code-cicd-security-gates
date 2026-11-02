# F05 clean runtime control

This test-only server HTML-escapes the `q` query parameter before rendering it.
It also supplies the response headers required for the clean-control scan to
avoid unrelated medium-severity ZAP findings.

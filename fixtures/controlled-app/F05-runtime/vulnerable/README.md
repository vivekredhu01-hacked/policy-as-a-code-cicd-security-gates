# F05 runtime vulnerability fixture

This test-only server reflects the `q` query parameter into HTML without
escaping it. OWASP ZAP is expected to identify the reflected input.

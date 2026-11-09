# Oracle

Validates:
- CA and leaf fingerprints changed from the precondition values.
- Leaf validity is ~1 year.
- Leaf verifies with the new CA and not with the old CA.
- Client trust bundle matches the new CA.
- HTTPS health check succeeds using the client CA.

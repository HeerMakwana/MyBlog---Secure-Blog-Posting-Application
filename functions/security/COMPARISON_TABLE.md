# Table 1: Comparison Table

| Test Case | Before Security | After Security | Result |
|---|---|---|---|
| User enumeration | Explicit responses like `Username or email already exists` and `User no longer exists` | Generic responses like `Registration failed. Please check your information.` and `Unauthorized access` | Mitigated |
| Stack trace exposure | Debug and raw runtime errors could surface in route responses | Client responses never include stack traces | Mitigated |
| Database error leakage | Raw `error.message` returned to user | Mongoose and internal errors normalized to safe messages | Mitigated |
| File path leakage | Possible through unsanitized exception messages | Internal/path details only in server logs, not API responses | Mitigated |
| Password in logs | No centralized masking policy | Keys like `password`, `token`, `secret` redacted before logging | Mitigated |
| Email in logs | Email and tokens at risk in ad-hoc logs | Email-like/sensitive fields masked in structured logs | Mitigated |

# Vulnerability #1: API Key Exposure in Application Logs

## Severity: HIGH

## Type: Information Disclosure / Credential Leakage

## Location
- **File**: `apps/ftso-data-provider/src/auth/auth.service.ts`
- **Line**: 11
- **Function**: `AuthService.constructor()`

## Description
The authentication service logs all API keys in plaintext to the application logs during initialization. This exposes sensitive authentication credentials that could be harvested by attackers with access to log files, log aggregation systems, or monitoring dashboards.

## Vulnerable Code
```typescript
constructor(private readonly configService: ConfigService) {
  const API_KEYS = configService.get<string[]>("api_keys");
  this.logger.log("API_KEYS: " + API_KEYS);  // ← VULNERABILITY: Logs all API keys
  if (!API_KEYS) {
    throw new Error("Env variables are missing (API_KEYS)");
  }
  if (API_KEYS.length === 0) {
    this.logger.warn("No API keys are set. This means that the no-one will be able to access the API.");
  }
  this.API_KEYS = API_KEYS;
}
```

## Attack Scenario
1. **Log File Access**: Attacker gains read access to application logs through:
   - Compromised log aggregation service (Splunk, ELK, CloudWatch)
   - Exposed log files in backup systems
   - Container logs in orchestration platforms (Kubernetes logs)
   - Shared development/staging environments

2. **Log Monitoring**: Attacker monitors real-time logs via:
   - Log streaming endpoints
   - Debug consoles
   - CI/CD pipeline logs
   - Error tracking services (Sentry, Bugsnag)

3. **API Key Harvesting**: Once API keys are obtained from logs, attacker can:
   - Access all protected API endpoints
   - Retrieve sensitive FTSO data
   - Manipulate commit/reveal data if combined with other vulnerabilities
   - Cause denial of service by exhausting API resources

## Impact
- **Confidentiality**: Complete compromise of API authentication mechanism
- **Availability**: Unauthorized API usage could exhaust rate limits or resources
- **Integrity**: Attackers with valid API keys can retrieve and potentially influence protocol data

## Evidence of Vulnerability
```bash
# Example log output on application startup:
[Nest] 12345  - 01/19/2025, 10:30:15 AM     LOG [AuthService] API_KEYS: 12345,abcdef,secret-key-2024,prod-ftso-key
```

All API keys are exposed in a single log line, making them trivial to extract with log parsing.

## Proof of Concept
1. Start the FTSO data provider service with `DATA_PROVIDER_CLIENT_API_KEYS="key1,key2,key3"`
2. Check application logs:
   ```bash
   docker logs ftso-data-provider 2>&1 | grep "API_KEYS:"
   ```
3. Extract the API keys from the log output
4. Use the extracted keys to access protected endpoints:
   ```bash
   curl -H "X-API-KEY: key1" http://localhost:3100/submit1/1000/0x123...
   ```

## Remediation Recommendations

### Immediate Fix (Priority: CRITICAL)
Remove the logging statement entirely:
```typescript
constructor(private readonly configService: ConfigService) {
  const API_KEYS = configService.get<string[]>("api_keys");
  // REMOVED: this.logger.log("API_KEYS: " + API_KEYS);
  if (!API_KEYS) {
    throw new Error("Env variables are missing (API_KEYS)");
  }
  if (API_KEYS.length === 0) {
    this.logger.warn("No API keys are set. This means that the no-one will be able to access the API.");
  }
  this.API_KEYS = API_KEYS;
}
```

### Improved Fix (Recommended)
Log only metadata about API keys:
```typescript
this.logger.log(`Loaded ${API_KEYS.length} API key(s)`);
// Optionally log hashed prefixes for debugging:
this.logger.debug(`API key prefixes: ${API_KEYS.map(k => k.substring(0, 4) + '...' + k.substring(k.length - 4)).join(', ')}`);
```

### Long-term Security Improvements
1. **Implement API Key Hashing**: Store only hashed versions of API keys
2. **Secret Scanning**: Add pre-commit hooks to prevent secrets in code
3. **Log Sanitization**: Implement automatic PII/secret redaction in logging framework
4. **Audit Logs**: Review all existing logs for exposed credentials
5. **Key Rotation**: Rotate all API keys that may have been exposed
6. **Secrets Management**: Use vault solutions (HashiCorp Vault, AWS Secrets Manager)

## Additional Security Concerns
This logging practice indicates potential broader issues:
- Other sensitive data may be logged elsewhere in the application
- No apparent secrets scanning in CI/CD pipeline
- Development practices may not include security review for logging statements

## References
- **CWE-532**: Insertion of Sensitive Information into Log File
- **OWASP Top 10 2021**: A09:2021 – Security Logging and Monitoring Failures
- **NIST 800-53**: AU-9 Protection of Audit Information

## Verification Status
✅ **VERIFIED** - Vulnerability confirmed through code review and testing

## Discovered By
Security Audit - Bug Bounty Program

## Date Reported
2025-01-19

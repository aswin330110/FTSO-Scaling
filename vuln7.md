# Vulnerability #7: Missing Input Length Validation

## Severity
**MEDIUM**

## Location
- **File:** `apps/ftso-data-provider/src/ftso-data-provider.controller.ts`
- **Lines:** 48, 74, 93, 111, 139
- **File:** `apps/ftso-data-provider/src/ftso-data-provider.service.ts`

## Description
String parameters (`submitAddress`, `feedId`, `submitSignaturesAddress`) accepted by API endpoints have no maximum length validation. This allows attackers to send extremely long strings, potentially causing:
1. Memory exhaustion
2. CPU exhaustion during string processing
3. Log file bloat
4. Cache pollution

## Vulnerable Code

### Controller
```typescript
@Get("submit1/:votingRoundId/:submitAddress")
async submit1(
  @Param("votingRoundId", ParseIntPipe) votingRoundId: number,
  @Param("submitAddress") submitAddress: string  // ← No max length
): Promise<PDPResponse> {
  this.logger.log(
    `Calling GET on submit1 with param: votingRoundId ${votingRoundId} and query param: submitAddress ${submitAddress}`
    // ← Logs entire string regardless of length
  );
  const data = await this.ftsoDataProviderService.getCommitData(votingRoundId, submitAddress);
  // ...
}

@Get("specific-feed/:feedId/:votingRoundId")
async feedWithProof(
  @Param("feedId") feedId: string,  // ← No max length
  @Param("votingRoundId", ParseIntPipe) votingRoundId: number
): Promise<ExternalFeedWithProofResponse> {
  // ...
}
```

### Service Layer - Cache Key Generation
```typescript
private async calculateOrGetRoundData(votingRoundId: number, submissionAddress: string, rewardEpoch: RewardEpoch) {
  const cached = this.votingRoundData.get(combine(votingRoundId, submissionAddress));
  // ← combine() creates cache key with unlimited string length
  // ...
  this.votingRoundData.set(combine(votingRoundId, submissionAddress), data);
  // ← Sets cache with potentially huge key
}

function combine(round: number, address: string): RoundAndAddress {
  return [round, address].toString();  // ← No length limit
}
```

## Impact

### 1. Memory Exhaustion
```bash
# Send 10MB address string
LONG_ADDR=$(python3 -c 'print("0x" + "A"*10000000)')
curl -H "X-API-KEY: 12345" \
  "http://localhost:3100/submit1/1000/$LONG_ADDR"

# Result:
# - String stored in memory
# - Logged (bloats log files)
# - Used as cache key (pollutes LRU cache)
# - Processed by toLowerCase() and hashing
```

### 2. CPU Exhaustion
```typescript
// String processing operations on huge inputs
voter.toLowerCase()  // O(n) operation on n-byte string
Buffer.from(feedIdHex.slice(2), "hex").toString("utf8")  // Expensive conversion
soliditySha3(encoded)  // Hash computation on large input
```

### 3. Log File Bloat
```javascript
// Controller logs entire parameter
this.logger.log(`... submitAddress ${submitAddress}`)
// If submitAddress is 1MB, every request generates 1MB+ log entry
```

### 4. LRU Cache Pollution
```javascript
// Attacker sends requests with different huge addresses
// Each creates a new cache entry with massive key
// Legitimate data gets evicted, cache becomes useless
```

## Proof of Concept
```bash
# Test 1: Send 10KB address
python3 << 'EOF'
import requests
long_addr = "0x" + "A" * 10000
response = requests.get(
    f"http://localhost:3100/submit1/1000/{long_addr}",
    headers={"X-API-KEY": "12345"}
)
print(f"Status: {response.status_code}")
EOF

# Test 2: Send 1MB feedId
GIANT_FEED=$(python3 -c 'print("0x01" + "FF"*500000)')
curl -H "X-API-KEY: 12345" \
  "http://localhost:3100/specific-feed/$GIANT_FEED/1000"

# Test 3: Memory exhaustion via cache pollution
for i in {1..1000}; do
  ADDR=$(python3 -c 'print("0x" + "A"*100000 + str('$i'))')
  curl -H "X-API-KEY: 12345" \
    "http://localhost:3100/submit1/1000/$ADDR" &
done
```

## Remediation

### Option 1: Add Length Validation with NestJS Pipes
```bash
npm install class-validator class-transformer
```

```typescript
import { IsString, IsEthereumAddress, MaxLength } from 'class-validator';

export class SubmitParamsDto {
  @IsInt()
  votingRoundId: number;

  @IsEthereumAddress()
  @MaxLength(42)  // Ethereum address: 0x + 40 hex chars
  submitAddress: string;
}

@Get("submit1/:votingRoundId/:submitAddress")
async submit1(@Param() params: SubmitParamsDto): Promise<PDPResponse> {
  // Validated parameters
}
```

### Option 2: Manual Validation
```typescript
@Get("submit1/:votingRoundId/:submitAddress")
async submit1(
  @Param("votingRoundId", ParseIntPipe) votingRoundId: number,
  @Param("submitAddress") submitAddress: string
): Promise<PDPResponse> {
  // Validate length
  if (submitAddress.length > 42) {
    throw new BadRequestException('submitAddress too long (max 42 characters)');
  }

  // Validate format
  if (!/^0x[0-9a-fA-F]{40}$/.test(submitAddress)) {
    throw new BadRequestException('Invalid Ethereum address format');
  }

  // ...
}
```

### Option 3: Custom Validation Pipe
```typescript
import { PipeTransform, Injectable, BadRequestException } from '@nestjs/common';
import { isAddress } from 'web3-utils';

@Injectable()
export class EthereumAddressPipe implements PipeTransform {
  transform(value: string) {
    if (!value || value.length > 42) {
      throw new BadRequestException('Invalid address length');
    }

    if (!isAddress(value)) {
      throw new BadRequestException('Invalid Ethereum address format');
    }

    return value.toLowerCase(); // Normalize
  }
}

@Get("submit1/:votingRoundId/:submitAddress")
async submit1(
  @Param("votingRoundId", ParseIntPipe) votingRoundId: number,
  @Param("submitAddress", EthereumAddressPipe) submitAddress: string
): Promise<PDPResponse> {
  // ...
}
```

### Recommended Limits
```typescript
const INPUT_LIMITS = {
  ethereumAddress: 42,    // 0x + 40 hex chars
  feedId: 44,             // 0x + 2 category + 40 name
  votingRoundId: 10,      // Max ~4 billion
  maxUrlLength: 2048,     // Standard URL limit
};
```

### Additional Protection: Global Validation Pipe
```typescript
// main.ts
import { ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(FtsoDataProviderModule);

  // Enable global validation
  app.useGlobalPipes(new ValidationPipe({
    whitelist: true,        // Strip unknown properties
    forbidNonWhitelisted: true,  // Throw error on unknown properties
    transform: true,        // Transform to DTO types
    transformOptions: {
      enableImplicitConversion: true,
    },
  }));

  // ...
}
```

## References
- OWASP: [Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- CWE-1284: Improper Validation of Specified Quantity in Input
- CWE-400: Uncontrolled Resource Consumption
- [NestJS Validation Documentation](https://docs.nestjs.com/techniques/validation)

## Verification Status
✅ **CONFIRMED** - No length validation found on string parameters in controller or service layers

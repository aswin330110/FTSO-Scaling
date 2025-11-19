# Vulnerability #2: Missing Ethereum Address Validation

## Severity
**MEDIUM**

## Location
- **File:** `apps/ftso-data-provider/src/ftso-data-provider.controller.ts`
- **Lines:** 48, 74, 111
- **File:** `apps/ftso-data-provider/src/ftso-data-provider.service.ts`
- **Lines:** 67-89

## Description
The `submitAddress` parameter in API endpoints is not validated to ensure it's a valid Ethereum address format before being used in cryptographic operations. The parameter is passed directly from the controller to the service layer and used in hash calculations without validation.

## Vulnerable Code

### Controller
```typescript
@Get("submit1/:votingRoundId/:submitAddress")
async submit1(
  @Param("votingRoundId", ParseIntPipe) votingRoundId: number,
  @Param("submitAddress") submitAddress: string  // ← No validation
): Promise<PDPResponse> {
  const data = await this.ftsoDataProviderService.getCommitData(votingRoundId, submitAddress);
  // ...
}
```

### Service
```typescript
async getCommitData(
  votingRoundId: number,
  submissionAddress: string  // ← No validation
): Promise<IPayloadMessage<ICommitData> | undefined> {
  const rewardEpoch = await this.rewardEpochManager.getRewardEpochForVotingEpochId(votingRoundId);
  const revealData = await this.calculateOrGetRoundData(votingRoundId, submissionAddress, rewardEpoch);
  const hash = CommitData.hashForCommit(
    submissionAddress,  // ← Used directly in hash calculation
    votingRoundId,
    revealData.random,
    revealData.encodedValues
  );
  // ...
}
```

### Hash Calculation
```typescript
export function hashForCommit(voter: Address, votingRoundId: number, random: string, feedValues: string): string {
  const types = ["address", "uint32", "uint256", "bytes"];
  const values = [voter.toLowerCase(), votingRoundId, random, feedValues];  // ← Assumes voter is valid
  const encoded = encodeParameters(types, values);
  const hash = soliditySha3(encoded);
  if (hash === undefined) throw new Error(`Unable to compute commit hash for ${votingRoundId}`);
  return hash;
}
```

## Impact
1. **Invalid Input Processing:** Non-address strings can be processed by the system
2. **Unexpected Behavior:** web3's `encodeParameters` may throw errors or produce unexpected results with invalid addresses
3. **Cache Pollution:** Invalid addresses can be cached in the LRU cache, consuming memory
4. **Error Exposure:** Stack traces may be exposed if web3 throws errors on invalid input

## Proof of Concept
```bash
# Test with invalid Ethereum address
curl -H "X-API-KEY: 12345" \
  http://localhost:3100/submit1/1000/invalid-address-format

# Test with excessively long string
curl -H "X-API-KEY: 12345" \
  http://localhost:3100/submit1/1000/$(python3 -c 'print("A"*10000)')

# Test with special characters
curl -H "X-API-KEY: 12345" \
  http://localhost:3100/submit1/1000/'<script>alert(1)</script>'
```

## Remediation

### Option 1: Add NestJS Validation Pipe
```typescript
import { IsEthereumAddress } from 'class-validator';

class SubmitParamsDto {
  @IsInt()
  votingRoundId: number;

  @IsEthereumAddress()
  submitAddress: string;
}

@Get("submit1/:votingRoundId/:submitAddress")
async submit1(@Param() params: SubmitParamsDto): Promise<PDPResponse> {
  // ...
}
```

### Option 2: Manual Validation
```typescript
import { isAddress } from 'web3-utils';

@Get("submit1/:votingRoundId/:submitAddress")
async submit1(
  @Param("votingRoundId", ParseIntPipe) votingRoundId: number,
  @Param("submitAddress") submitAddress: string
): Promise<PDPResponse> {
  if (!isAddress(submitAddress)) {
    throw new BadRequestException('Invalid Ethereum address format');
  }
  // ...
}
```

## References
- OWASP: [Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- CWE-20: Improper Input Validation
- Web3.js: [isAddress() documentation](https://web3js.readthedocs.io/en/v1.2.11/web3-utils.html#isaddress)

## Verification Status
✅ **CONFIRMED** - Verified by code review and tracing data flow from controller to hash function

# Vulnerability #8: Potential Hex Injection in Feed ID Processing

## Severity
**LOW to MEDIUM**

## Location
- **File:** `apps/ftso-data-provider/src/ftso-data-provider.service.ts`
- **Lines:** 284-293

## Description
The `decodeFeed()` function processes user-supplied `feedId` values without sufficient validation before using them in `Buffer.from()` with hex encoding. While there is a length check, malformed hex strings could cause unexpected behavior or errors.

## Vulnerable Code
```typescript
function decodeFeed(feedIdHex: string): FeedId {
  feedIdHex = unPrefix0x(feedIdHex);
  if (feedIdHex.length !== 42) {
    throw new Error(`Invalid feed string: ${feedIdHex}`);
  }

  const category = parseInt(feedIdHex.slice(0, 2));  // ← No validation of parse result
  const name = Buffer.from(feedIdHex.slice(2), "hex").toString("utf8").replaceAll("\0", "");
  // ← Buffer.from will accept invalid hex but may produce unexpected results
  return { category, name };
}
```

## Issues

### 1. No NaN Check on parseInt
```typescript
const category = parseInt(feedIdHex.slice(0, 2));
// If first 2 chars are not valid hex digits, parseInt returns NaN
// NaN is then used as category ID
```

### 2. Invalid Hex Handling
```typescript
Buffer.from(feedIdHex.slice(2), "hex")
// If feedIdHex contains non-hex characters:
// - Buffer.from silently ignores invalid characters
// - May produce unexpected byte sequences
```

### 3. No Hex Validation
```typescript
// Missing validation that all characters are valid hex [0-9a-fA-F]
```

## Impact
1. **Invalid Category:** Category could be `NaN` if first 2 characters aren't valid hex
2. **Data Corruption:** Invalid hex chars are silently ignored by Buffer.from, producing wrong data
3. **Cache Pollution:** Invalid feed IDs may be cached with corrupted data
4. **Logic Errors:** Code expecting valid category numbers may malfunction with NaN

## Proof of Concept
```bash
# Test 1: Non-hex characters in category
curl -H "X-API-KEY: 12345" \
  "http://localhost:3100/specific-feed/0xZZ0000000000000000000000000000000000000000/1000"
# category = NaN

# Test 2: Non-hex characters in name portion
curl -H "X-API-KEY: 12345" \
  "http://localhost:3100/specific-feed/0x01GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG/1000"
# Invalid hex characters silently ignored

# Test 3: Mixed case and special chars
curl -H "X-API-KEY: 12345" \
  "http://localhost:3100/specific-feed/0x01<script>alert(1)</script>0000000000/1000"
# Length check fails but demonstrates insufficient validation
```

## Node.js Buffer.from Behavior
```javascript
// Testing Buffer.from hex parsing
console.log(Buffer.from("FF", "hex"));     // <Buffer ff> ✓ valid
console.log(Buffer.from("FG", "hex"));     // <Buffer 0f> ✗ G ignored!
console.log(Buffer.from("ZZ", "hex"));     // <Buffer> ✗ empty buffer
console.log(Buffer.from("<script>", "hex")); // <Buffer> ✗ all ignored

// Testing parseInt
console.log(parseInt("FF", 16));  // 255 ✓
console.log(parseInt("ZZ", 16));  // NaN ✗
```

## Remediation

### Recommended Fix
```typescript
function decodeFeed(feedIdHex: string): FeedId {
  // Remove 0x prefix
  feedIdHex = unPrefix0x(feedIdHex);

  // Validate length
  if (feedIdHex.length !== 42) {
    throw new Error(`Invalid feed string length: ${feedIdHex.length}, expected 42`);
  }

  // Validate hex format
  if (!/^[0-9a-fA-F]{42}$/.test(feedIdHex)) {
    throw new Error(`Invalid feed string format: contains non-hex characters`);
  }

  // Parse category with validation
  const category = parseInt(feedIdHex.slice(0, 2), 16);
  if (isNaN(category)) {
    throw new Error(`Invalid feed category: ${feedIdHex.slice(0, 2)}`);
  }

  // Safe to parse hex now that we've validated
  const nameHex = feedIdHex.slice(2);
  const name = Buffer.from(nameHex, "hex").toString("utf8").replaceAll("\0", "");

  return { category, name };
}
```

### Helper Function for Hex Validation
```typescript
function isValidHex(str: string): boolean {
  return /^[0-9a-fA-F]*$/.test(str);
}

function unPrefix0x(str: string): string {
  const unprefixed = str.startsWith("0x") || str.startsWith("0X")
    ? str.slice(2)
    : str;

  if (!isValidHex(unprefixed)) {
    throw new Error(`Invalid hex string: ${str}`);
  }

  return unprefixed;
}
```

### Alternative: Use Web3 Utilities
```typescript
import { isHexStrict, hexToBytes } from 'web3-utils';

function decodeFeed(feedIdHex: string): FeedId {
  // Validate hex format
  if (!isHexStrict(feedIdHex)) {
    throw new Error(`Invalid hex format: ${feedIdHex}`);
  }

  feedIdHex = feedIdHex.slice(2); // Remove 0x

  if (feedIdHex.length !== 42) {
    throw new Error(`Invalid feed string length: ${feedIdHex.length}`);
  }

  const category = parseInt(feedIdHex.slice(0, 2), 16);
  const nameBytes = hexToBytes('0x' + feedIdHex.slice(2));
  const name = Buffer.from(nameBytes).toString("utf8").replaceAll("\0", "");

  return { category, name };
}
```

## Additional Validation in Controller
```typescript
@Get("specific-feed/:feedId/:votingRoundId")
async feedWithProof(
  @Param("feedId") feedId: string,
  @Param("votingRoundId", ParseIntPipe) votingRoundId: number
): Promise<ExternalFeedWithProofResponse> {
  // Validate feedId format before processing
  if (!/^0x[0-9a-fA-F]{42}$/.test(feedId)) {
    throw new BadRequestException('Invalid feed ID format');
  }
  // ...
}
```

## References
- Node.js [Buffer.from() documentation](https://nodejs.org/api/buffer.html#static-method-bufferfromstring-encoding)
- MDN: [parseInt() with radix](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/parseInt)
- CWE-20: Improper Input Validation
- OWASP: [Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)

## Verification Status
✅ **CONFIRMED** - Code review shows:
- No NaN validation on parseInt result
- No hex format validation before Buffer.from
- Missing input validation in controller

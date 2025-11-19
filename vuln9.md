# Vulnerability #9: Information Disclosure in Error Messages

## Severity
**LOW to MEDIUM**

## Location
- **File:** `apps/ftso-data-provider/src/ftso-data-provider.service.ts`
- **Lines:** 208, 255, 260

## Description
Error messages expose internal system details including voting round IDs, database connection information, and backend service details. While some error context is necessary for debugging, excessive details can aid attackers in reconnaissance and exploitation.

## Vulnerable Code

### Error 1: Internal Server Error with Cause
```typescript
try {
  return calculateResultsForVotingRound(dataResponse.data);
} catch (e) {
  this.logger.error(`Error calculating result: ${errorString(e)}`);
  throw new InternalServerErrorException(
    `Unable to calculate result for epoch ${votingRoundId}`,
    { cause: e }  // ← Exposes internal error details to client
  );
}
```

### Error 2: Value Provider Connection Details
```typescript
try {
  response = await retry(
    async () =>
      await this.feedValueProviderClient.feedValueProviderApi.getFeedValues(votingRoundId, {
        feeds: supportedFeeds.map(feed => decodeFeed(feed.id)),
      })
  );
} catch (e) {
  if (e instanceof RetryError) {
    throw new Error(
      `Failed to get feed values for epoch ${votingRoundId}, error connecting to value provider:\n${e.cause}`
      // ← Exposes internal service details and error stack
    );
  }
}
```

### Error 3: Backend Response Exposure
```typescript
if (response.status < 200 || response.status >= 300) {
  throw new Error(
    `Failed to get feed values for epoch ${votingRoundId}: ${response.data}`
    // ← Exposes backend response data
  );
}
```

## Impact
1. **Information Leakage:** Attackers learn about internal architecture
2. **Service Enumeration:** Reveals existence and URLs of backend services
3. **Error Details:** Stack traces and error causes help find vulnerabilities
4. **System Reconnaissance:** Epoch IDs and timing information disclosed
5. **Database Schema:** Error messages may reveal table/column names

## Exposed Information Examples

### Example 1: Stack Trace
```json
{
  "statusCode": 500,
  "message": "Unable to calculate result for epoch 1234",
  "error": "Internal Server Error",
  "cause": {
    "stack": "Error: Cannot read property 'merkleRoot' of undefined\n    at calculateResultsForVotingRound (ftso-calculation-logic.ts:45)\n    at FtsoDataProviderService.prepareCalculationResultData (ftso-data-provider.service.ts:205)\n    ...",
    "message": "Cannot read property 'merkleRoot' of undefined"
  }
}
```

### Example 2: Backend Service Details
```
Error: Failed to get feed values for epoch 1234, error connecting to value provider:
RetryError: Maximum retries exceeded
  at retry (retry.ts:67)
  Caused by: Error: connect ECONNREFUSED 192.168.1.10:3101
    at TCPConnectWrap.afterConnect [as oncomplete] (net.js:1148:16)
```

### Example 3: Backend Response
```
Error: Failed to get feed values for epoch 1234: {"error":"Database connection pool exhausted","sqlState":"HY000","errno":1040}
```

## Proof of Concept
```bash
# Test 1: Trigger calculation error
curl -H "X-API-KEY: 12345" \
  "http://localhost:3100/data/999999999" | jq

# Response exposes internal error with cause

# Test 2: Invalid feed ID to trigger decodeFeed error
curl -H "X-API-KEY: 12345" \
  "http://localhost:3100/specific-feed/invalid/1000" | jq

# Response may expose validation error details

# Test 3: Request future epoch to trigger data unavailability
curl -H "X-API-KEY: 12345" \
  "http://localhost:3100/medianCalculationResults/999999999" | jq
```

## Remediation

### Option 1: Generic Error Messages for Clients
```typescript
try {
  return calculateResultsForVotingRound(dataResponse.data);
} catch (e) {
  // Log detailed error for debugging
  this.logger.error(`Error calculating result for epoch ${votingRoundId}: ${errorString(e)}`);

  // Return generic error to client
  throw new InternalServerErrorException(
    'Unable to calculate voting round result'
    // Do NOT include: votingRoundId, cause, stack trace
  );
}
```

### Option 2: Categorized Error Messages
```typescript
try {
  response = await retry(/*...*/);
} catch (e) {
  // Log detailed error
  this.logger.error(
    `Feed value provider connection failed for epoch ${votingRoundId}`,
    { error: e, provider: this.feedValueProviderClient.baseURL }
  );

  // Return sanitized error
  if (e instanceof RetryError) {
    throw new ServiceUnavailableException(
      'External data provider temporarily unavailable'
    );
  }
  throw new InternalServerErrorException(
    'Failed to retrieve feed values'
  );
}
```

### Option 3: Custom Exception Filter
```typescript
import { ExceptionFilter, Catch, ArgumentsHost, HttpException } from '@nestjs/common';

@Catch()
export class SanitizedExceptionFilter implements ExceptionFilter {
  catch(exception: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse();
    const request = ctx.getRequest();

    let status = 500;
    let message = 'Internal server error';

    if (exception instanceof HttpException) {
      status = exception.getStatus();
      const exceptionResponse = exception.getResponse();

      // Sanitize the response - remove stack traces, causes, etc.
      if (typeof exceptionResponse === 'object') {
        message = (exceptionResponse as any).message || message;
      } else {
        message = exceptionResponse;
      }
    }

    // Log detailed error server-side
    console.error('Exception occurred:', {
      timestamp: new Date().toISOString(),
      path: request.url,
      method: request.method,
      exception: exception,
    });

    // Return sanitized error to client
    response.status(status).json({
      statusCode: status,
      message: message,
      // Do NOT include: exception, cause, stack, path details
    });
  }
}

// Apply globally in main.ts
app.useGlobalFilters(new SanitizedExceptionFilter());
```

### Option 4: Environment-Based Error Details
```typescript
// configuration.ts
export default () => ({
  // ...
  debugMode: process.env.NODE_ENV !== 'production',
});

// service.ts
try {
  return calculateResultsForVotingRound(dataResponse.data);
} catch (e) {
  this.logger.error(`Error calculating result: ${errorString(e)}`);

  const debugMode = this.configService.get<boolean>('debugMode');

  if (debugMode) {
    // Development: include details
    throw new InternalServerErrorException(
      `Unable to calculate result for epoch ${votingRoundId}`,
      { cause: e }
    );
  } else {
    // Production: generic message
    throw new InternalServerErrorException(
      'Unable to calculate result'
    );
  }
}
```

## Best Practices

### 1. Separate Logging and User Messages
```typescript
// ✓ GOOD
this.logger.error(`Detailed error for logs: ${e.stack}`);
throw new InternalServerErrorException('Generic user message');

// ✗ BAD
throw new InternalServerErrorException(`Detailed error: ${e.stack}`);
```

### 2. Error Code System
```typescript
enum ErrorCode {
  CALCULATION_FAILED = 'CALC_001',
  PROVIDER_UNAVAILABLE = 'PROV_001',
  INVALID_INPUT = 'INPT_001',
}

throw new InternalServerErrorException({
  code: ErrorCode.CALCULATION_FAILED,
  message: 'Unable to process request',
  // Internal details logged separately
});
```

### 3. Structured Logging
```typescript
this.logger.error('Calculation failed', {
  votingRoundId,
  error: e.message,
  stack: e.stack,
  timestamp: new Date().toISOString(),
  requestId: request.id,
});
```

## References
- OWASP: [Error Handling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html)
- CWE-209: Generation of Error Message Containing Sensitive Information
- CWE-211: Externally-Generated Error Message Containing Sensitive Information
- [NestJS Exception Filters](https://docs.nestjs.com/exception-filters)

## Verification Status
✅ **CONFIRMED** - Multiple error messages expose internal details:
- Line 208: Exposes epoch IDs and error causes
- Line 255: Exposes value provider connection details
- Line 260: Exposes backend response data

# Vulnerability #6: Docker Container Runs as Root

## Severity
**MEDIUM**

## Location
- **File:** `Dockerfile`
- **Lines:** 1-29

## Description
The Docker container does not specify a non-root user, causing the application to run with root privileges inside the container. This violates the principle of least privilege and increases the impact of potential container breakout vulnerabilities.

## Vulnerable Code
```dockerfile
FROM node:22-slim@sha256:4a4884e8a44826194dff92ba316264f392056cbe243dcc9fd3551e71cea02b90 AS nodemodules

WORKDIR /app

COPY package.json yarn.lock ./
RUN yarn install --frozen-lockfile --network-timeout 100000

FROM node:22-slim@sha256:4a4884e8a44826194dff92ba316264f392056cbe243dcc9fd3551e71cea02b90 AS build

WORKDIR /app

COPY --from=nodemodules /app/node_modules /app/node_modules
COPY . ./

RUN yarn build
RUN yarn build ftso-reward-calculation-process

FROM node:22-slim@sha256:4a4884e8a44826194dff92ba316264f392056cbe243dcc9fd3551e71cea02b90 AS runtime

WORKDIR /app

COPY --from=nodemodules /app/node_modules /app/node_modules
COPY --from=build /app/dist /app/dist

COPY . .

CMD ["bash"]
# ← Missing: USER node or USER 1001
```

## Impact
1. **Privilege Escalation:** If an attacker compromises the application, they have root access in the container
2. **Container Breakout:** Root privileges make container escape vulnerabilities more severe
3. **File System Access:** Attacker can modify any file in the container
4. **Process Manipulation:** Attacker can kill or manipulate any process
5. **Compliance Issues:** Violates security best practices and compliance requirements (PCI-DSS, SOC2, etc.)

## Risk Scenarios

### Scenario 1: Application Vulnerability + Root = Full Container Compromise
```javascript
// If there's an RCE vulnerability in the Node.js application
// Attacker can execute as root:
child_process.exec('cat /etc/shadow')  // Can read any file
child_process.exec('apt-get install malware')  // Can install packages
```

### Scenario 2: Dependency Vulnerability
```bash
# If a malicious npm package is installed
# It runs with root privileges during build or runtime
# Can modify system files, install backdoors, etc.
```

### Scenario 3: Container Breakout
```bash
# Known container escape vulnerabilities (CVE-2019-5736, etc.)
# Are more severe when container runs as root
# Attacker gains root on host system
```

## Proof of Concept
```bash
# Build and run the container
docker build -t ftso-scaling .
docker run -it ftso-scaling bash

# Inside container - check current user
id
# Output: uid=0(root) gid=0(root) groups=0(root)  ← Running as root!

# Demonstrate elevated privileges
touch /etc/malicious-file  # Succeeds because we're root
cat /etc/shadow  # Can read shadow file
```

## Remediation

### Recommended Fix
```dockerfile
FROM node:22-slim@sha256:4a4884e8a44826194dff92ba316264f392056cbe243dcc9fd3551e71cea02b90 AS nodemodules

WORKDIR /app

COPY package.json yarn.lock ./
RUN yarn install --frozen-lockfile --network-timeout 100000

FROM node:22-slim@sha256:4a4884e8a44826194dff92ba316264f392056cbe243dcc9fd3551e71cea02b90 AS build

WORKDIR /app

COPY --from=nodemodules /app/node_modules /app/node_modules
COPY . ./

RUN yarn build
RUN yarn build ftso-reward-calculation-process

FROM node:22-slim@sha256:4a4884e8a44826194dff92ba316264f392056cbe243dcc9fd3551e71cea02b90 AS runtime

# Create non-root user
RUN groupadd -r ftso && useradd -r -g ftso ftso

WORKDIR /app

# Copy files and set ownership
COPY --from=nodemodules --chown=ftso:ftso /app/node_modules /app/node_modules
COPY --from=build --chown=ftso:ftso /app/dist /app/dist
COPY --chown=ftso:ftso . .

# Switch to non-root user
USER ftso

# Update CMD to run Node.js directly
CMD ["node", "dist/apps/ftso-data-provider/apps/ftso-data-provider/src/main.js"]
```

### Alternative: Use Existing Node User
```dockerfile
FROM node:22-slim@sha256:4a4884e8a44826194dff92ba316264f392056cbe243dcc9fd3551e71cea02b90 AS runtime

WORKDIR /app

COPY --from=nodemodules --chown=node:node /app/node_modules /app/node_modules
COPY --from=build --chown=node:node /app/dist /app/dist
COPY --chown=node:node . .

# Use the existing 'node' user from base image
USER node

CMD ["node", "dist/apps/ftso-data-provider/apps/ftso-data-provider/src/main.js"]
```

### Additional Security Hardening
```dockerfile
FROM node:22-slim@sha256:4a4884e8a44826194dff92ba316264f392056cbe243dcc9fd3551e71cea02b90 AS runtime

# Run as non-root user
USER node

WORKDIR /home/node/app

COPY --from=nodemodules --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/dist ./dist
COPY --chown=node:node package.json ./

# Set read-only filesystem hints
ENV NODE_ENV=production

# Drop all capabilities except required ones
# (configured in docker-compose or kubernetes)

CMD ["node", "dist/apps/ftso-data-provider/apps/ftso-data-provider/src/main.js"]
```

### Docker Compose Security
```yaml
version: '3.8'
services:
  ftso-data-provider:
    image: ftso-scaling:latest
    user: "1000:1000"  # Enforce non-root
    read_only: true  # Read-only root filesystem
    cap_drop:
      - ALL  # Drop all capabilities
    security_opt:
      - no-new-privileges:true  # Prevent privilege escalation
    tmpfs:
      - /tmp  # Writable tmp for Node.js
```

## Verification
```bash
# After applying fix - verify non-root user
docker build -t ftso-scaling:fixed .
docker run -it ftso-scaling:fixed bash
id
# Output: uid=1000(node) gid=1000(node) groups=1000(node)  ← Not root!

# Verify cannot write to system files
touch /etc/test  # Should fail: Permission denied
```

## References
- OWASP: [Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
- CWE-250: Execution with Unnecessary Privileges
- [Docker Best Practices](https://docs.docker.com/develop/dev-best-practices/)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)

## Verification Status
✅ **CONFIRMED** - No `USER` directive found in Dockerfile, container runs as root by default

# Scanning GitHub Repositories for Mass Assignment Vulnerabilities

This guide explains how to use SpringSecure CLI to scan GitHub repositories for mass assignment vulnerabilities.

## Quick Start

### Scan Any Public GitHub Repository

Simply provide the GitHub repository URL:

```bash
node cli.js https://github.com/username/spring-boot-project
```

The tool will:
1. Clone the repository to a temporary directory
2. Scan all Java and YAML files
3. Display vulnerabilities found
4. Clean up temporary files automatically

## Examples

### Example 1: Scan a Public Spring Boot Project

```bash
node cli.js https://github.com/spring-projects/spring-petclinic --verbose
```

This will scan the Spring PetClinic project and show detailed recommendations.

### Example 2: Generate JSON Report from Repository

```bash
node cli.js https://github.com/username/my-api --json -o security-report.json
```

### Example 3: Fail CI/CD Build on High Severity Issues

```bash
node cli.js https://github.com/username/production-api --fail-on-high --json -o report.json
```

## What Gets Detected

The scanner looks for these mass assignment vulnerabilities:

### 🔴 HIGH Severity (CWE-915, CWE-200)

1. **Lombok @Data on Entity Classes**
   - Automatically generates setters for ALL fields
   - Allows attackers to modify sensitive fields like `isAdmin`, `role`, `balance`

2. **Direct Entity Binding in Controllers**
   - `@RequestBody` directly bound to entity classes
   - No DTO layer protection
   - Example:
     ```java
     @PostMapping("/users")
     public User create(@RequestBody User user) { // VULNERABLE!
         return userService.save(user);
     }
     ```

3. **Sensitive Fields Without @JsonIgnore**
   - Fields like `password`, `token`, `secret` exposed in API responses
   - Missing `@JsonIgnore` annotation

4. **Public Setters on Sensitive Fields**
   - Public setters on `role`, `isAdmin`, `balance`, `creditLimit`
   - Can be exploited via mass assignment

### 🟡 MEDIUM Severity (CWE-915, CWE-20)

5. **Unsafe Jackson Configuration**
   - `fail-on-unknown-properties: false` in application.yml
   - Allows arbitrary property binding

6. **Missing Input Validation**
   - `@RequestBody` without `@Valid` annotation
   - No Bean Validation constraints

7. **Dangerous JPA Cascade Configuration**
   - Using `CascadeType.ALL` on relationships
   - Can lead to unintended data modifications

### 🔵 LOW Severity

8. **Unsafe Orphan Removal**
   - `orphanRemoval=true` without lifecycle callbacks

9. **Permissive MVC Configuration**
   - Silently ignoring missing handlers

## Understanding the Output

### Console Output

```
═══════════════════════════════════════════════════════
  SpringSecure - Mass Assignment Vulnerability Scanner
═══════════════════════════════════════════════════════

📄 src/main/java/com/example/User.java
   Found 2 issue(s): 2 HIGH

   1. HIGH - Lombok @Data on Entity
      Line: 8
      Issue: Entity class uses @Data annotation which generates public setters...
      Fix: Replace @Data with @Getter and use @Setter only on safe fields...

───────────────────────────────────────────────────────
Summary:
  Total Files Scanned: 15
  Total Issues: 8
  ● High Severity: 3
  ● Medium Severity: 4
  ● Low Severity: 1
───────────────────────────────────────────────────────
```

### JSON Output

```json
{
  "timestamp": "2025-11-12T22:00:00.000Z",
  "summary": {
    "high": 3,
    "medium": 4,
    "low": 1,
    "total": 8
  },
  "vulnerabilities": [
    {
      "type": "Lombok @Data on Entity",
      "severity": "HIGH",
      "description": "Entity class uses @Data annotation...",
      "line": 8,
      "recommendation": "Replace @Data with @Getter...",
      "file": "/path/to/User.java",
      "cwe": "CWE-915"
    }
  ]
}
```

## Best Practices

1. **Run Before Deployment**
   - Scan your repository before deploying to production
   - Use `--fail-on-high` in CI/CD pipelines

2. **Regular Scans**
   - Schedule weekly scans of your repositories
   - Track vulnerability trends over time

3. **Fix High Severity First**
   - Prioritize HIGH severity issues
   - These are actively exploitable

4. **Use DTOs**
   - Create separate DTO classes for API requests
   - Never bind directly to entity classes

5. **Add Validation**
   - Always use `@Valid` with `@RequestBody`
   - Implement Bean Validation constraints

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-node@v2
        with:
          node-version: '18'
      - name: Install SpringSecure
        run: |
          git clone https://github.com/Harshith1201/FY-Team-08-Detection-of-Mass-assignment-Vulnerabilities-in-REST-APIs.git scanner
          cd scanner
          npm install
      - name: Run Security Scan
        run: |
          cd scanner
          node cli.js .. --fail-on-high --json -o ../security-report.json
      - name: Upload Report
        uses: actions/upload-artifact@v2
        with:
          name: security-report
          path: security-report.json
```

## License

MIT


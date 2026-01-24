# SpringSecure CLI - Feature Overview

## Core Features

### 1. 🔍 Comprehensive Vulnerability Detection

Detects **10 types** of mass assignment vulnerabilities across **3 severity levels**:

- **HIGH**: Direct exploits (Lombok @Data, Direct Entity Binding, Exposed Sensitive Fields, Public Setters)
- **MEDIUM**: Configuration issues (Jackson config, Missing validation, JPA cascades)
- **LOW**: Potential risks (Orphan removal, MVC config)

Each vulnerability includes:
- CWE classification
- Line number
- Detailed description
- Actionable recommendation

### 2. ⚡ Dynamic Analysis (IAST)

Verify static findings against a running application:
- **Interactive Probing**: Sends safe requests to detected endpoints
- **Mass Assignment Verification**: Checks if injected fields are reflected in responses
- **Intelligent Fuzzing**: Users context-aware payloads based on entity types

### 3. 📦 Multiple Scan Targets

**Local Files:**
```bash
node cli.js UserController.java
```

**Local Directories:**
```bash
node cli.js /path/to/spring-project
```

**GitHub Repositories:**
```bash
node cli.js https://github.com/username/repo
```

### 4. 📊 Flexible Output Formats

**Console (Default):**
- Colorized output
- Grouped by file
- Summary statistics
- Verbose mode available

**JSON:**
```bash
node cli.js src/ --json -o report.json
```
- Machine-readable
- Includes timestamp
- Summary statistics
- Full vulnerability details

**Text:**
```bash
node cli.js src/ --text -o report.txt
```
- Plain text format
- Good for documentation
- Email-friendly

### 5. ⚡ CI/CD Integration

**Exit Codes:**
- `0` - No issues or below threshold
- `1` - Issues found above threshold

**Fail on High Severity:**
```bash
node cli.js src/ --fail-on-high
```

**Fail on Medium+ Severity:**
```bash
node cli.js src/ --fail-on-medium
```

Perfect for:
- GitHub Actions
- Jenkins
- GitLab CI
- Travis CI
- CircleCI

### 6. 🎯 Smart Pattern Detection

**Enhanced Detection:**
- Lombok annotation combinations
- Entity class patterns
- Controller method signatures
- JPA relationship configurations
- Jackson deserialization settings
- Sensitive field patterns

**Recognized Patterns:**
- Common entity names (User, Account, Order, Product, etc.)
- Sensitive fields (password, token, secret, role, isAdmin, etc.)
- Spring annotations (@Entity, @RestController, @RequestBody, etc.)
- Lombok annotations (@Data, @Setter, @AllArgsConstructor, etc.)

### 7. 🧹 Automatic Cleanup

When scanning GitHub repositories:
- Clones to temporary directory
- Scans all Java/YAML files
- Automatically cleans up temp files
- No manual cleanup needed

### 8. 📝 Detailed Recommendations

Each vulnerability includes:
- **What**: Clear description of the issue
- **Why**: Security implications
- **How**: Step-by-step fix instructions
- **CWE**: Industry-standard classification

Example:
```
Type: Lombok @Data on Entity
Severity: HIGH
Description: Entity class uses @Data annotation which generates public 
             setters for all fields, including sensitive ones like roles, 
             permissions, and internal state.
Recommendation: Replace @Data with @Getter and use @Setter only on safe 
                fields. Consider using DTOs for API boundaries.
CWE: CWE-915
```

### 9. 🚀 Fast & Efficient

- Recursive directory scanning
- Parallel file processing
- Efficient pattern matching
- Minimal dependencies

### 10. 🛡️ Security-First Design

**Detects Real-World Exploits:**
- Mass assignment attacks
- Privilege escalation
- Data exposure
- Unauthorized modifications

**Based on OWASP Guidelines:**
- OWASP Top 10
- OWASP API Security Top 10
- CWE classifications

### 11. 📚 Comprehensive Documentation

- README.md - Full documentation
- QUICKSTART.md - Get started in 5 minutes
- SCANNING_REPOS.md - GitHub repository scanning guide
- FEATURES.md - This file
- MIGRATION_SUMMARY.md - Web to CLI migration details

## Supported File Types

- `.java` - Java source files
- `.yml` - YAML configuration
- `.yaml` - YAML configuration

## Excluded Directories

Automatically skips:
- `node_modules/`
- `target/`
- `build/`
- `.git/`

## Command-Line Options

```
Options:
  -V, --version          Output version number
  -o, --output <file>    Output file path for report
  -f, --format <type>    Output format: console, json, text
  -v, --verbose          Show detailed recommendations
  --json                 Output as JSON
  --text                 Output as text
  --fail-on-high         Exit with error on high severity
  --fail-on-medium       Exit with error on medium+ severity
  --url <url>            Base URL for dynamic analysis
  -h, --help             Display help
```

## Use Cases

1. **Pre-Commit Checks** - Scan before committing code
2. **CI/CD Pipeline** - Automated security checks
3. **Code Review** - Identify vulnerabilities during review
4. **Security Audits** - Comprehensive project scanning
5. **Learning Tool** - Understand mass assignment vulnerabilities
6. **Compliance** - Meet security requirements

## Future Enhancements

Potential additions:
- Custom rule definitions
- Whitelist/blacklist patterns
- HTML report generation
- IDE integrations
- Real-time file watching
- Severity customization
- Fix suggestions with code patches

## License

MIT


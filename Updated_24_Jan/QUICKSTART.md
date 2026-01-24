# Quick Start Guide

## Installation

1. Install dependencies:
```bash
npm install
```

## Try It Out

### 1. Scan the example files

```bash
node cli.js examples/
```

This will scan the example vulnerable Java files and show you the detected issues.
```

### 2. Verify with Dynamic Analysis (Optional)

If you have a running application:
```bash
node cli.js examples/ --url http://localhost:8080
```
This attempts to verify the found vulnerabilities by sending requests to the running app.

### 2. Scan with verbose output

```bash
node cli.js examples/ --verbose
```

Shows detailed recommendations for fixing each vulnerability.

### 3. Generate a JSON report

```bash
node cli.js examples/ --json -o report.json
```

Creates a JSON report file that can be consumed by other tools.

### 4. Test CI/CD integration

```bash
node cli.js examples/ --fail-on-high
```

This will exit with code 1 because high severity issues were found. Perfect for CI/CD pipelines!

## Scan Your Own Project

Point the tool at your Spring Boot project:

```bash
node cli.js /path/to/your/spring-boot-project
```

Or scan a specific file:

```bash
node cli.js /path/to/UserController.java -v
```

## What Gets Detected?

The tool currently detects these mass assignment vulnerabilities:

✅ **Lombok @Data on Entity classes** (HIGH)
✅ **Direct entity binding in controllers** (HIGH)  
✅ **Unsafe Jackson configuration** (MEDIUM)
✅ **Missing @Valid annotations** (MEDIUM)
✅ **Lombok @Setter on entities** (MEDIUM)
✅ **Lombok @AllArgsConstructor on entities** (LOW)

## Next Steps

- Integrate into your CI/CD pipeline
- Generate reports for security audits
- Fix the detected vulnerabilities
- Run regular scans on your codebase

## Need Help?

Run `node cli.js --help` to see all available options.


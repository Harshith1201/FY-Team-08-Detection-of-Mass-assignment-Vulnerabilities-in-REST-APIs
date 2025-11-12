/**
 * Enhanced vulnerability detection logic with better pattern matching
 */

function detectVulnerabilities(code, filename = '') {
    const vulnerabilities = [];
    const ext = filename.toLowerCase();

    if (ext.endsWith('.java')) {
        vulnerabilities.push(...analyzeJavaFile(code, filename));
    } else if (ext.endsWith('.yml') || ext.endsWith('.yaml')) {
        vulnerabilities.push(...analyzeYamlFile(code, filename));
    }

    return vulnerabilities;
}

/**
 * Analyze Java files with comprehensive checks
 */
function analyzeJavaFile(code, filename) {
    const vulnerabilities = [];

    // Check for class-level issues
    vulnerabilities.push(...checkLombokAnnotations(code, filename));
    vulnerabilities.push(...checkEntityExposure(code, filename));

    // Check for controller issues
    vulnerabilities.push(...checkControllerBindings(code, filename));
    vulnerabilities.push(...checkValidationAnnotations(code, filename));

    // Check for JPA/Hibernate issues
    vulnerabilities.push(...checkJpaRelationships(code, filename));

    // Check for setter methods on sensitive fields
    vulnerabilities.push(...checkSensitiveFieldSetters(code, filename));

    return vulnerabilities;
}

/**
 * Check for Lombok annotation issues
 */
function checkLombokAnnotations(code, filename) {
    const vulnerabilities = [];
    const lines = code.split('\n');

    let hasEntity = false;
    let hasData = false;
    let hasSetter = false;
    let hasAllArgsConstructor = false;
    let hasNoArgsConstructor = false;

    lines.forEach((line, idx) => {
        if (line.includes('@Entity') || line.includes('@Document')) {
            hasEntity = true;
        }
        if (line.includes('@Data')) {
            hasData = true;
            if (hasEntity) {
                vulnerabilities.push({
                    type: 'Lombok @Data on Entity',
                    severity: 'HIGH',
                    description: 'Entity class uses @Data annotation which generates public setters for all fields, including sensitive ones like roles, permissions, and internal state.',
                    line: idx + 1,
                    recommendation: 'Replace @Data with @Getter and use @Setter only on safe fields. Consider using DTOs for API boundaries.',
                    file: filename,
                    cwe: 'CWE-915'
                });
            }
        }
        if (line.includes('@Setter') && hasEntity) {
            hasSetter = true;
            vulnerabilities.push({
                type: 'Lombok @Setter on Entity',
                severity: 'MEDIUM',
                description: 'Entity class uses @Setter which may expose fields to mass assignment attacks.',
                line: idx + 1,
                recommendation: 'Use @Setter only on specific safe fields, or use DTOs for data transfer.',
                file: filename,
                cwe: 'CWE-915'
            });
        }
        if (line.includes('@AllArgsConstructor') && hasEntity) {
            hasAllArgsConstructor = true;
        }
        if (line.includes('@NoArgsConstructor') && hasEntity) {
            hasNoArgsConstructor = true;
        }
    });

    // Check for dangerous combinations
    if (hasEntity && hasAllArgsConstructor && hasNoArgsConstructor) {
        vulnerabilities.push({
            type: 'Dangerous Lombok Constructor Combination',
            severity: 'MEDIUM',
            description: 'Entity has both @AllArgsConstructor and @NoArgsConstructor which can be exploited with reflection.',
            line: findLineNumber(code, '@AllArgsConstructor'),
            recommendation: 'Use @RequiredArgsConstructor with @NonNull on required fields only.',
            file: filename,
            cwe: 'CWE-915'
        });
    }

    return vulnerabilities;
}

/**
 * Check for entity exposure patterns
 */
function checkEntityExposure(code, filename) {
    const vulnerabilities = [];

    // Check for @JsonIgnore missing on sensitive fields
    const sensitiveFields = ['password', 'token', 'secret', 'apiKey', 'privateKey', 'salt'];
    const lines = code.split('\n');

    let inEntity = false;
    lines.forEach((line, idx) => {
        if (line.includes('@Entity') || line.includes('@Document')) {
            inEntity = true;
        }

        if (inEntity) {
            sensitiveFields.forEach(field => {
                const fieldPattern = new RegExp(`private\\s+\\w+\\s+${field}`, 'i');
                if (fieldPattern.test(line) && !lines[idx - 1]?.includes('@JsonIgnore')) {
                    vulnerabilities.push({
                        type: 'Sensitive Field Without @JsonIgnore',
                        severity: 'HIGH',
                        description: `Sensitive field '${field}' is not marked with @JsonIgnore and may be exposed in API responses.`,
                        line: idx + 1,
                        recommendation: `Add @JsonIgnore annotation above the ${field} field to prevent serialization.`,
                        file: filename,
                        cwe: 'CWE-200'
                    });
                }
            });
        }
    });

    return vulnerabilities;
}

/**
 * Check for direct entity exposure in controllers
 */
function checkControllerBindings(code, filename) {
    const vulnerabilities = [];
    const lines = code.split('\n');

    let isController = false;
    lines.forEach((line, idx) => {
        if (line.includes('@RestController') || line.includes('@Controller')) {
            isController = true;
        }
    });

    if (!isController) return vulnerabilities;

    // Check for @RequestBody with entity classes
    lines.forEach((line, idx) => {
        if (line.includes('@RequestBody')) {
            const entityPattern = /@RequestBody\s+(\w+)\s+/;
            const match = line.match(entityPattern);

            if (match) {
                const paramType = match[1];

                // Common entity class names or if code contains entity definition
                if (paramType.match(/^(User|Account|Order|Product|Customer|Employee|Payment|Transaction)$/i) ||
                    (code.includes(`class ${paramType}`) && code.includes('@Entity'))) {

                    vulnerabilities.push({
                        type: 'Direct Entity Binding in Controller',
                        severity: 'HIGH',
                        description: `Controller method binds @RequestBody directly to entity class '${paramType}' without DTO layer. This allows clients to modify any field.`,
                        line: idx + 1,
                        recommendation: `Create a ${paramType}DTO class with only modifiable fields. Map DTO to entity in service layer.`,
                        file: filename,
                        cwe: 'CWE-915'
                    });
                }
            }
        }
    });

    return vulnerabilities;
}

/**
 * Check for validation annotations
 */
function checkValidationAnnotations(code, filename) {
    const vulnerabilities = [];
    const lines = code.split('\n');

    lines.forEach((line, idx) => {
        if (line.includes('@RequestBody') && !line.includes('@Valid') && !line.includes('@Validated')) {
            vulnerabilities.push({
                type: 'Missing Input Validation',
                severity: 'MEDIUM',
                description: 'Request body parameter lacks validation annotations.',
                line: idx + 1,
                recommendation: 'Add @Valid or @Validated annotation and use Bean Validation constraints.',
                file: filename,
                cwe: 'CWE-20'
            });
        }
    });

    return vulnerabilities;
}

/**
 * Check for JPA relationship issues
 */
function checkJpaRelationships(code, filename) {
    const vulnerabilities = [];
    const lines = code.split('\n');

    lines.forEach((line, idx) => {
        // Check for cascade = CascadeType.ALL on relationships
        if ((line.includes('@OneToMany') || line.includes('@ManyToMany')) &&
            line.includes('cascade') && line.includes('CascadeType.ALL')) {
            vulnerabilities.push({
                type: 'Dangerous JPA Cascade Configuration',
                severity: 'MEDIUM',
                description: 'Relationship uses CascadeType.ALL which can lead to unintended data modifications through mass assignment.',
                line: idx + 1,
                recommendation: 'Use specific cascade types (PERSIST, MERGE) instead of ALL. Handle deletions explicitly.',
                file: filename,
                cwe: 'CWE-915'
            });
        }

        // Check for orphanRemoval without proper safeguards
        if (line.includes('orphanRemoval = true') && !code.includes('@PreRemove')) {
            vulnerabilities.push({
                type: 'Unsafe Orphan Removal',
                severity: 'LOW',
                description: 'orphanRemoval=true without lifecycle callbacks may lead to unintended deletions.',
                line: idx + 1,
                recommendation: 'Add @PreRemove lifecycle callback to validate deletions.',
                file: filename,
                cwe: 'CWE-915'
            });
        }
    });

    return vulnerabilities;
}

/**
 * Check for setters on sensitive fields
 */
function checkSensitiveFieldSetters(code, filename) {
    const vulnerabilities = [];
    const sensitiveFields = ['role', 'permission', 'isAdmin', 'isActive', 'balance', 'credit', 'creditLimit'];
    const lines = code.split('\n');

    sensitiveFields.forEach(field => {
        const setterPattern = new RegExp(`public\\s+void\\s+set${field}`, 'i');
        lines.forEach((line, idx) => {
            if (setterPattern.test(line)) {
                vulnerabilities.push({
                    type: 'Public Setter on Sensitive Field',
                    severity: 'HIGH',
                    description: `Public setter found for sensitive field '${field}' which can be exploited via mass assignment.`,
                    line: idx + 1,
                    recommendation: `Remove public setter for ${field} or make it private/protected. Update field through business logic methods only.`,
                    file: filename,
                    cwe: 'CWE-915'
                });
            }
        });
    });

    return vulnerabilities;
}

/**
 * Analyze YAML configuration files
 */
function analyzeYamlFile(code, filename) {
    const vulnerabilities = [];

    // Check for unsafe Jackson config
    if (code.includes('fail-on-unknown-properties: false')) {
        vulnerabilities.push({
            type: 'Unsafe Jackson Deserialization',
            severity: 'MEDIUM',
            description: 'Jackson configured to accept unknown properties, enabling mass assignment attacks.',
            line: findLineNumber(code, 'fail-on-unknown-properties'),
            recommendation: 'Set fail-on-unknown-properties to true or remove this configuration.',
            file: filename,
            cwe: 'CWE-915'
        });
    }

    if (code.includes('fail-on-ignored-properties: false')) {
        vulnerabilities.push({
            type: 'Unsafe Jackson Configuration',
            severity: 'MEDIUM',
            description: 'Jackson configured to ignore @JsonIgnore annotations.',
            line: findLineNumber(code, 'fail-on-ignored-properties'),
            recommendation: 'Set fail-on-ignored-properties to true.',
            file: filename,
            cwe: 'CWE-915'
        });
    }

    // Check for permissive MVC configuration
    if (code.includes('throw-exception-if-no-handler-found: false')) {
        vulnerabilities.push({
            type: 'Permissive MVC Configuration',
            severity: 'LOW',
            description: 'MVC configured to silently ignore missing handlers.',
            line: findLineNumber(code, 'throw-exception-if-no-handler-found'),
            recommendation: 'Enable exception throwing for missing handlers.',
            file: filename,
            cwe: 'CWE-755'
        });
    }

    return vulnerabilities;
}

function findLineNumber(code, searchTerm) {
    const lines = code.split('\n');
    for (let i = 0; i < lines.length; i++) {
        if (lines[i].includes(searchTerm)) {
            return i + 1;
        }
    }
    return 1;
}

function getSeverityStats(vulnerabilities) {
    return {
        high: vulnerabilities.filter(v => v.severity === 'HIGH').length,
        medium: vulnerabilities.filter(v => v.severity === 'MEDIUM').length,
        low: vulnerabilities.filter(v => v.severity === 'LOW').length,
        total: vulnerabilities.length
    };
}

module.exports = {
    detectVulnerabilities,
    getSeverityStats
};


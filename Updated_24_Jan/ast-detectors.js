/**
 * AST-based vulnerability detectors
 */

const {
    parseJavaCode,
    extractAnnotations,
    extractClassName,
    findClassDeclarations,
    findMethodDeclarations,
    findFieldDeclarations
} = require('./ast-analyzer');

/**
 * Check for Lombok @Data on Entity classes using AST
 */
function checkLombokAnnotationsAST(code, filename) {
    const vulnerabilities = [];
    const parseResult = parseJavaCode(code);

    if (!parseResult.success) {
        // Fall back to regex if parsing fails
        return [];
    }

    const classes = findClassDeclarations(parseResult.ast);

    for (const classNode of classes) {
        const classAnnotations = extractAnnotations(classNode);
        const className = extractClassName(classNode);

        const hasEntity = classAnnotations.some(ann =>
            ann === 'Entity' || ann === 'javax.persistence.Entity'
        );

        if (hasEntity) {
            // Check for @Data
            if (classAnnotations.some(ann => ann === 'Data' || ann === 'lombok.Data')) {
                vulnerabilities.push({
                    type: 'Lombok @Data on Entity',
                    severity: 'HIGH',
                    description: `Entity class '${className}' uses @Data annotation which generates public setters for all fields, including sensitive ones like roles, permissions, and internal state.`,
                    line: getLineNumber(classNode),
                    recommendation: 'Replace @Data with @Getter and use @Setter only on safe fields. Consider using DTOs for API boundaries.',
                    file: filename,
                    cwe: 'CWE-915'
                });
            }

            // Check for @Setter
            if (classAnnotations.some(ann => ann === 'Setter' || ann === 'lombok.Setter')) {
                vulnerabilities.push({
                    type: 'Lombok @Setter on Entity',
                    severity: 'MEDIUM',
                    description: `Entity class '${className}' uses @Setter annotation which may expose fields to mass assignment.`,
                    line: getLineNumber(classNode),
                    recommendation: 'Use @Setter only on specific safe fields, not at class level.',
                    file: filename,
                    cwe: 'CWE-915'
                });
            }

            // Check for @AllArgsConstructor
            if (classAnnotations.some(ann => ann === 'AllArgsConstructor' || ann === 'lombok.AllArgsConstructor')) {
                vulnerabilities.push({
                    type: 'Lombok @AllArgsConstructor on Entity',
                    severity: 'LOW',
                    description: `Entity class '${className}' uses @AllArgsConstructor which may be exploited in combination with other patterns.`,
                    line: getLineNumber(classNode),
                    recommendation: 'Consider using @RequiredArgsConstructor or custom constructors.',
                    file: filename,
                    cwe: 'CWE-915'
                });
            }
        }
    }

    return vulnerabilities;
}

/**
 * Check for sensitive fields without @JsonIgnore using AST
 */
function checkEntityExposureAST(code, filename) {
    const vulnerabilities = [];
    const parseResult = parseJavaCode(code);

    if (!parseResult.success) {
        return [];
    }

    const classes = findClassDeclarations(parseResult.ast);
    const sensitiveFields = ['password', 'token', 'secret', 'apiKey', 'privateKey', 'salt', 'hash'];

    for (const classNode of classes) {
        const classAnnotations = extractAnnotations(classNode);
        const className = extractClassName(classNode);

        const hasEntity = classAnnotations.some(ann =>
            ann === 'Entity' || ann === 'javax.persistence.Entity'
        );

        if (hasEntity) {
            const fields = findFieldDeclarations(classNode);

            for (const field of fields) {
                const fieldName = extractFieldName(field);
                const fieldAnnotations = extractAnnotations(field);

                // Check if field is sensitive
                if (sensitiveFields.some(sf => fieldName.toLowerCase().includes(sf))) {
                    const hasJsonIgnore = fieldAnnotations.some(ann =>
                        ann === 'JsonIgnore' || ann === 'com.fasterxml.jackson.annotation.JsonIgnore'
                    );

                    if (!hasJsonIgnore) {
                        vulnerabilities.push({
                            type: 'Sensitive Field Without @JsonIgnore',
                            severity: 'HIGH',
                            description: `Sensitive field '${fieldName}' in entity '${className}' is not marked with @JsonIgnore and may be exposed in API responses.`,
                            line: getLineNumber(field),
                            recommendation: `Add @JsonIgnore annotation above the ${fieldName} field to prevent serialization.`,
                            file: filename,
                            cwe: 'CWE-200'
                        });
                    }
                }
            }
        }
    }

    return vulnerabilities;
}

/**
 * Extract field name from field declaration
 */
function extractFieldName(fieldNode) {
    if (fieldNode.children && fieldNode.children.variableDeclaratorList) {
        const varList = fieldNode.children.variableDeclaratorList[0];
        if (varList.children && varList.children.variableDeclarator) {
            const varDecl = Array.isArray(varList.children.variableDeclarator)
                ? varList.children.variableDeclarator[0]
                : varList.children.variableDeclarator;
            if (varDecl.children && varDecl.children.variableDeclaratorId) {
                const varId = varDecl.children.variableDeclaratorId[0];
                if (varId.children && varId.children.Identifier) {
                    return varId.children.Identifier[0].image;
                }
            }
        }
    }
    return '';
}

/**
 * Get line number from AST node
 */
function getLineNumber(node) {
    // Try to find line number from location info
    if (node.location && node.location.startLine) {
        return node.location.startLine;
    }
    return 1;
}

/**
 * Check for direct entity binding in controllers using AST
 */
function checkControllerBindingsAST(code, filename) {
    const vulnerabilities = [];
    const parseResult = parseJavaCode(code);

    if (!parseResult.success) {
        return [];
    }

    const classes = findClassDeclarations(parseResult.ast);
    const entityNames = ['User', 'Account', 'Order', 'Product', 'Customer', 'Payment', 'Transaction'];

    for (const classNode of classes) {
        const classAnnotations = extractAnnotations(classNode);

        const isController = classAnnotations.some(ann =>
            ann === 'RestController' || ann === 'Controller' ||
            ann === 'org.springframework.web.bind.annotation.RestController' ||
            ann === 'org.springframework.stereotype.Controller'
        );

        if (isController) {
            // Try to get class-level mapping
            const classMapping = extractRequestMapping(classNode);
            const methods = findMethodDeclarations(classNode);

            for (const method of methods) {
                const params = extractMethodParameters(method);
                const methodMapping = extractRequestMapping(method);

                // Determine effective path and method
                // Simple logical path combination: classMapping + methodMapping (path)
                let fullPath = '';
                if (classMapping.path) fullPath += classMapping.path;
                if (methodMapping.path) fullPath += methodMapping.path.startsWith('/') ? methodMapping.path : '/' + methodMapping.path;

                // Clean up double slashes
                fullPath = fullPath.replace('//', '/');

                const httpMethod = methodMapping.method || 'POST'; // Default to POST logic if uncertain but binding body

                for (const param of params) {
                    const hasRequestBody = param.annotations.some(ann =>
                        ann === 'RequestBody' || ann === 'org.springframework.web.bind.annotation.RequestBody'
                    );

                    if (hasRequestBody) {
                        // Check if parameter type is likely an entity
                        if (entityNames.some(entity => param.type.includes(entity))) {
                            vulnerabilities.push({
                                type: 'Direct Entity Binding in Controller',
                                severity: 'HIGH',
                                description: `Controller method binds @RequestBody directly to entity class '${param.type}' without DTO layer. This allows clients to modify any field.`,
                                line: getLineNumber(method),
                                recommendation: `Create a ${param.type}DTO class with only modifiable fields. Map DTO to entity in service layer.`,
                                file: filename,
                                cwe: 'CWE-915',
                                metadata: {
                                    endpoint: fullPath,
                                    method: httpMethod,
                                    entity: param.type
                                }
                            });
                        }

                        // Check for missing @Valid
                        const hasValid = param.annotations.some(ann =>
                            ann === 'Valid' || ann === 'Validated' ||
                            ann === 'javax.validation.Valid' || ann === 'org.springframework.validation.annotation.Validated'
                        );

                        if (!hasValid) {
                            vulnerabilities.push({
                                type: 'Missing Input Validation',
                                severity: 'MEDIUM',
                                description: 'Request body parameter lacks validation annotations.',
                                line: getLineNumber(method),
                                recommendation: 'Add @Valid or @Validated annotation and use Bean Validation constraints.',
                                file: filename,
                                cwe: 'CWE-20'
                            });
                        }
                    }
                }
            }
        }
    }

    return vulnerabilities;
}

/**
 * Extract RequestMapping or specific mapping info from node
 */
function extractRequestMapping(node) {
    const result = { path: '', method: null };

    // Helper to extract string value from annotation
    // This is VERY simplified. AST structure for values is complex.
    // We assume the first string argument is the path.
    const getPathFromAnnotation = (annNode) => {
        // This requires deep traversal depending on CST structure
        // Since we don't have full CST navigation helpers here, we'll try a regex hack on the node's source range if possible
        // But we don't have source range here easily.
        // For now, return empty to avoid crashes, improving this requires 'java-parser' deep knowledge
        return '';
    };

    if (node.children && node.children.modifier) {
        for (const mod of node.children.modifier) {
            if (mod.children && mod.children.annotation) {
                const ann = mod.children.annotation[0];
                // Check normal annotation or marker annotation
                let name = '';
                if (ann.children.normalAnnotation) {
                    name = ann.children.normalAnnotation[0].children.typeName[0].children.Identifier[0].image;
                } else if (ann.children.singleElementAnnotation) {
                    name = ann.children.singleElementAnnotation[0].children.typeName[0].children.Identifier[0].image;

                    // Try to extract value
                    // This is hard without full CST traversal utility
                } else if (ann.children.markerAnnotation) {
                    name = ann.children.markerAnnotation[0].children.typeName[0].children.Identifier[0].image;
                }

                if (name === 'RequestMapping') {
                    // Assume default is GET unless specified, but usually used for class level
                } else if (name === 'GetMapping') {
                    result.method = 'GET';
                } else if (name === 'PostMapping') {
                    result.method = 'POST';
                } else if (name === 'PutMapping') {
                    result.method = 'PUT';
                } else if (name === 'PatchMapping') {
                    result.method = 'PATCH';
                } else if (name === 'DeleteMapping') {
                    result.method = 'DELETE';
                }
            }
        }
    }

    return result;
}

/**
 * Extract method parameters with annotations
 */
function extractMethodParameters(methodNode) {
    const params = [];

    if (methodNode.children && methodNode.children.formalParameterList) {
        const paramList = methodNode.children.formalParameterList[0];
        if (paramList.children && paramList.children.formalParameter) {
            const formalParams = Array.isArray(paramList.children.formalParameter)
                ? paramList.children.formalParameter
                : [paramList.children.formalParameter];

            for (const param of formalParams) {
                const annotations = extractAnnotations(param);
                const type = extractParameterType(param);
                params.push({ annotations, type });
            }
        }
    }

    return params;
}

/**
 * Extract parameter type
 */
function extractParameterType(paramNode) {
    if (paramNode.children && paramNode.children.unannType) {
        const unannType = paramNode.children.unannType[0];
        if (unannType.children && unannType.children.unannClassOrInterfaceType) {
            const classType = unannType.children.unannClassOrInterfaceType[0];
            if (classType.children && classType.children.unannClassType) {
                const unannClassType = Array.isArray(classType.children.unannClassType)
                    ? classType.children.unannClassType[0]
                    : classType.children.unannClassType;
                if (unannClassType.children && unannClassType.children.Identifier) {
                    return unannClassType.children.Identifier[0].image;
                }
            }
        }
    }
    return '';
}

module.exports = {
    checkLombokAnnotationsAST,
    checkEntityExposureAST,
    checkControllerBindingsAST
};


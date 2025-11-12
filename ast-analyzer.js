/**
 * AST-based Java vulnerability detection using java-parser
 */

const { parse } = require('java-parser');

/**
 * Parse Java code into AST
 */
function parseJavaCode(code) {
    try {
        const ast = parse(code);
        return { success: true, ast };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

/**
 * Extract all annotations from a node
 * For class nodes, check the parent classDeclaration
 */
function extractAnnotations(node) {
    const annotations = [];

    // For class nodes, check the classDeclaration parent
    if (node._classDeclaration) {
        const classDecl = node._classDeclaration;
        if (classDecl.children && classDecl.children.classModifier) {
            const modifiers = Array.isArray(classDecl.children.classModifier)
                ? classDecl.children.classModifier
                : [classDecl.children.classModifier];

            for (const modifier of modifiers) {
                if (modifier.children && modifier.children.annotation) {
                    const annNodes = Array.isArray(modifier.children.annotation)
                        ? modifier.children.annotation
                        : [modifier.children.annotation];

                    for (const ann of annNodes) {
                        if (ann.children && ann.children.typeName) {
                            const typeName = Array.isArray(ann.children.typeName)
                                ? ann.children.typeName[0]
                                : ann.children.typeName;
                            const name = extractTypeName(typeName);
                            annotations.push(name);
                        }
                    }
                }
            }
        }
    }

    // Also check direct annotation children (for fields, methods, parameters)
    if (node && node.children && node.children.annotation) {
        const annotationNodes = Array.isArray(node.children.annotation)
            ? node.children.annotation
            : [node.children.annotation];

        for (const ann of annotationNodes) {
            if (ann.children && ann.children.typeName) {
                const typeName = Array.isArray(ann.children.typeName)
                    ? ann.children.typeName[0]
                    : ann.children.typeName;
                const name = extractTypeName(typeName);
                annotations.push(name);
            }
        }
    }

    return annotations;
}

/**
 * Extract type name from AST node
 */
function extractTypeName(typeNameNode) {
    if (!typeNameNode || !typeNameNode.children) return '';
    
    if (typeNameNode.children.Identifier) {
        const ids = Array.isArray(typeNameNode.children.Identifier)
            ? typeNameNode.children.Identifier
            : [typeNameNode.children.Identifier];
        return ids.map(id => id.image).join('.');
    }
    
    return '';
}

/**
 * Extract class name from class declaration
 */
function extractClassName(classDeclaration) {
    if (classDeclaration.children && classDeclaration.children.typeIdentifier) {
        const typeId = classDeclaration.children.typeIdentifier[0];
        if (typeId.children && typeId.children.Identifier) {
            return typeId.children.Identifier[0].image;
        }
    }
    return '';
}

/**
 * Find all class declarations in AST with their parent classDeclaration
 */
function findClassDeclarations(ast) {
    const classes = [];

    function traverse(node, parent = null) {
        if (!node) return;

        // Look for classDeclaration which contains classModifier (annotations)
        if (node.name === 'classDeclaration') {
            // Attach the classDeclaration to normalClassDeclaration for annotation access
            if (node.children && node.children.normalClassDeclaration) {
                const normalClass = Array.isArray(node.children.normalClassDeclaration)
                    ? node.children.normalClassDeclaration[0]
                    : node.children.normalClassDeclaration;

                // Store reference to parent classDeclaration for annotation access
                normalClass._classDeclaration = node;
                classes.push(normalClass);
            }
        }

        if (node.children) {
            for (const key in node.children) {
                const child = node.children[key];
                if (Array.isArray(child)) {
                    child.forEach(c => traverse(c, node));
                } else {
                    traverse(child, node);
                }
            }
        }
    }

    traverse(ast);
    return classes;
}

/**
 * Find all method declarations in a class
 */
function findMethodDeclarations(classNode) {
    const methods = [];
    
    function traverse(node) {
        if (!node) return;
        
        if (node.name === 'methodDeclaration') {
            methods.push(node);
        }
        
        if (node.children) {
            for (const key in node.children) {
                const child = node.children[key];
                if (Array.isArray(child)) {
                    child.forEach(traverse);
                } else {
                    traverse(child);
                }
            }
        }
    }
    
    traverse(classNode);
    return methods;
}

/**
 * Find all field declarations in a class
 */
function findFieldDeclarations(classNode) {
    const fields = [];
    
    function traverse(node) {
        if (!node) return;
        
        if (node.name === 'fieldDeclaration') {
            fields.push(node);
        }
        
        if (node.children) {
            for (const key in node.children) {
                const child = node.children[key];
                if (Array.isArray(child)) {
                    child.forEach(traverse);
                } else {
                    traverse(child);
                }
            }
        }
    }
    
    traverse(classNode);
    return fields;
}

module.exports = {
    parseJavaCode,
    extractAnnotations,
    extractTypeName,
    extractClassName,
    findClassDeclarations,
    findMethodDeclarations,
    findFieldDeclarations
};


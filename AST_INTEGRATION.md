# AST-Based Analysis Integration

## Overview

SpringSecure CLI now uses **Abstract Syntax Tree (AST) parsing** for accurate vulnerability detection in Java code. This provides significantly better accuracy compared to simple regex pattern matching.

## What is AST-Based Analysis?

**Abstract Syntax Tree (AST)** is a tree representation of the syntactic structure of source code. Each node in the tree represents a construct in the code (class, method, annotation, field, etc.).

### Benefits of AST-Based Analysis

✅ **More Accurate** - Understands code structure, not just text patterns  
✅ **Fewer False Positives** - Ignores comments and strings  
✅ **Fewer False Negatives** - Detects complex patterns  
✅ **Context Aware** - Understands relationships between code elements  
✅ **Robust** - Handles various code formatting styles  

### Comparison: Regex vs AST

**Regex-Based Detection:**
```java
// This comment has @Data annotation - FALSE POSITIVE!
String message = "Use @Data carefully"; // FALSE POSITIVE!
```

**AST-Based Detection:**
- ✅ Ignores comments
- ✅ Ignores string literals
- ✅ Only detects actual annotations in code

## Implementation

### Architecture

```
analyzer.js (Main)
    ↓
ast-detectors.js (AST-based detection)
    ↓
ast-analyzer.js (AST parsing utilities)
    ↓
java-parser (Library)
```

### Files

1. **ast-analyzer.js** - AST parsing and traversal utilities
   - `parseJavaCode()` - Parse Java code into AST
   - `findClassDeclarations()` - Find all classes in AST
   - `findMethodDeclarations()` - Find all methods in a class
   - `findFieldDeclarations()` - Find all fields in a class
   - `extractAnnotations()` - Extract annotations from nodes
   - `extractClassName()` - Get class name from AST node

2. **ast-detectors.js** - AST-based vulnerability detectors
   - `checkLombokAnnotationsAST()` - Detect Lombok issues using AST
   - `checkEntityExposureAST()` - Detect sensitive field exposure using AST
   - `checkControllerBindingsAST()` - Detect direct entity binding using AST

3. **analyzer.js** - Main analyzer with smart fallback
   - Uses AST-based detection first
   - Falls back to regex if AST parsing fails
   - Combines results from multiple detectors

### Smart Fallback Strategy

```javascript
// Try AST-based detection first
const astResults = checkLombokAnnotationsAST(code, filename);

// If AST parsing succeeded, use AST results
if (astResults.length > 0) {
    vulnerabilities.push(...astResults);
} else {
    // Fall back to regex-based detection
    vulnerabilities.push(...checkLombokAnnotations(code, filename));
}
```

This ensures the tool always works, even if:
- Java code has syntax errors
- Code uses unsupported Java features
- AST parser encounters issues

## Detected Patterns

### 1. Lombok @Data on Entity (AST-Based)

**What it detects:**
```java
@Entity
@Data  // ← Detected by AST
public class User {
    private String password;
}
```

**How it works:**
1. Parse Java code into AST
2. Find all class declarations
3. Extract annotations from each class
4. Check if class has both `@Entity` and `@Data`
5. Report vulnerability with exact line number

### 2. Sensitive Fields Without @JsonIgnore (AST-Based)

**What it detects:**
```java
@Entity
public class User {
    private String password;  // ← No @JsonIgnore - VULNERABLE!
}
```

**How it works:**
1. Find all classes with `@Entity` annotation
2. Find all field declarations in the class
3. Check if field name contains sensitive keywords (password, token, secret, etc.)
4. Check if field has `@JsonIgnore` annotation
5. Report if sensitive field lacks `@JsonIgnore`

### 3. Direct Entity Binding in Controllers (AST-Based)

**What it detects:**
```java
@RestController
public class UserController {
    @PostMapping("/users")
    public User create(@RequestBody User user) {  // ← Direct entity binding!
        return userService.save(user);
    }
}
```

**How it works:**
1. Find all classes with `@RestController` or `@Controller`
2. Find all method declarations in the controller
3. Extract method parameters
4. Check if parameter has `@RequestBody` annotation
5. Check if parameter type is an entity class (User, Account, Order, etc.)
6. Check if parameter has `@Valid` annotation
7. Report vulnerabilities

## Accuracy Improvements

### Before AST (Regex-Based)

**False Positives:**
- Matches annotations in comments
- Matches annotations in strings
- Matches partial annotation names

**False Negatives:**
- Misses annotations with whitespace variations
- Misses annotations with full package names
- Misses complex annotation patterns

### After AST (AST-Based)

**Eliminated False Positives:**
- ✅ Ignores comments completely
- ✅ Ignores string literals
- ✅ Only matches actual code annotations

**Eliminated False Negatives:**
- ✅ Handles any whitespace/formatting
- ✅ Handles full package names (`@lombok.Data`, `@Data`)
- ✅ Handles complex annotation patterns

## Performance

**AST Parsing:**
- Slightly slower than regex (milliseconds per file)
- Negligible impact on overall scan time
- Worth the accuracy improvement

**Fallback:**
- If AST parsing fails, regex is used
- No performance penalty for malformed code
- Best of both worlds

## Future Enhancements

Potential improvements:
- [ ] AST-based JPA relationship detection
- [ ] AST-based setter method detection
- [ ] AST-based validation annotation detection
- [ ] Support for Kotlin code
- [ ] Support for Groovy code
- [ ] Custom annotation detection rules

## Testing

Run tests to verify AST-based detection:

```bash
# Test with example files
node cli.js examples/ --verbose

# Test with a real Spring Boot project
node cli.js /path/to/spring-project --verbose

# Test with GitHub repository
node cli.js https://github.com/spring-projects/spring-petclinic --verbose
```

## Troubleshooting

### AST Parsing Fails

If you see regex-based results instead of AST-based:
1. Check if Java code has syntax errors
2. Verify java-parser is installed: `npm list java-parser`
3. Check console for parsing errors (use `--verbose`)

### Unexpected Results

If detection seems incorrect:
1. Verify annotations are at class level (not in comments)
2. Check if annotations use full package names
3. Report issues on GitHub with code samples

## License

MIT


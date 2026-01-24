# References & Resources

Here are the key resources and standards that informed the design and implementation of this tool.

## Vulnerability Concepts

### Mass Assignment (Auto-Binding)
*   **OWASP API Security Top 10 (2023)**
    *   [API3:2023 - Broken Object Property Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/) (Successor to Mass Assignment)
    *   [API6:2019 - Mass Assignment](https://owasp.org/www-project-api-security/editions/2019/en/0xa6-mass-assignment/) (Previous classic definition)
*   **CWE (Common Weakness Enumeration)**
    *   [CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)
*   **Spring Boot Specifics**
    *   [Spring MVC Documentation - Data Binding](https://docs.spring.io/spring-framework/reference/web/webmvc/mvc-controller/ann-methods/databinder.html)
    *   [Baeldung: Mass Assignment in Spring](https://www.baeldung.com/spring-mass-assignment)

## Analysis Methodologies

### Static Application Security Testing (SAST)
*   This tool uses **AST (Abstract Syntax Tree)** analysis to understand code structure.
    *   Library used: [java-parser](https://www.npmjs.com/package/java-parser) (based on Prettier's Java parser).

### Interactive Application Security Testing (IAST)
*   The **Dynamic Analysis** feature implements an IAST approach:
    *   It uses static knowledge (from the AST) to guide dynamic attacks.
    *   This is often referred to as "Gray-box testing".
    *   Reference: [OWASP Gray Box Testing](https://owasp.org/www-community/Gray_Box_Testing)

## Tool Implementation
*   **Source Code**: The logic for this tool (including `dynamic-scanner.js` and `ast-detectors.js`) was custom-developed for this project.
*   **Node.js Ecosystem**: Built using `commander`, `axios`, and `chalk`.

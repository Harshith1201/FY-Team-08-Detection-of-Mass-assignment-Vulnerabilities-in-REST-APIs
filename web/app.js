// SpringSecure Mass Assignment Vulnerability Detection Tool - JavaScript

// Application data
const vulnerabilityTypes = [
    {
        name: "Lombok @Data Exposure",
        severity: "HIGH", 
        description: "Entity classes using @Data annotation expose sensitive fields through auto-generated setters",
        example: "@Entity\n@Data\npublic class User {\n    private String username;\n    private boolean isAdmin; // VULNERABLE\n}",
        mitigation: "Use @Getter and selective @Setter annotations instead of @Data"
    },
    {
        name: "Direct Entity Binding",
        severity: "HIGH",
        description: "Controllers directly bind @RequestBody to entity classes without DTO layer",
        example: "@PostMapping(\"/users\")\npublic User create(@RequestBody User user) {\n    return userService.save(user);\n}",
        mitigation: "Create DTO classes for request binding and map to entities in service layer"
    },
    {
        name: "Unsafe Jackson Config",
        severity: "MEDIUM",
        description: "Jackson deserialization configured to ignore unknown properties",
        example: "spring:\n  jackson:\n    deserialization:\n      fail-on-unknown-properties: false",
        mitigation: "Set fail-on-unknown-properties to true or implement property whitelisting"
    },
    {
        name: "Missing Input Validation",
        severity: "MEDIUM",
        description: "Request parameters lack proper validation annotations",
        example: "public void updateUser(@RequestBody User user) {\n    // No @Valid annotation\n}",
        mitigation: "Add @Valid, @NotNull, and other validation annotations"
    }
];

const codeExamples = {
    lombok: `@Entity
@Data  // VULNERABLE: Generates setters for ALL fields
public class User {
    private String username;
    private String email;
    private boolean isAdmin;  // Can be mass assigned!
    private String role;      // Can be mass assigned!
    private double creditLimit; // Can be mass assigned!
}`,
    
    controller: `@RestController
public class UserController {
    
    @PostMapping("/users")
    public User createUser(@RequestBody User user) {  // VULNERABLE
        return userService.save(user);
    }
    
    @PutMapping("/users/{id}")
    public User updateUser(@PathVariable Long id, 
                          @RequestBody User user) {  // VULNERABLE
        user.setId(id);
        return userService.update(user);
    }
}`,
    
    config: `# application.yml
spring:
  jackson:
    deserialization:
      fail-on-unknown-properties: false  # VULNERABLE`
};

// Application state
let currentSection = 'dashboard';
let currentDoc = 'installation';
let vulnerabilityChart = null;

// DOM Content Loaded
document.addEventListener('DOMContentLoaded', function() {
    initializeNavigation();
    initializeCodeAnalyzer();
    initializeDocumentation();
    initializeChart();
    
    // Initialize Prism.js for syntax highlighting
    if (typeof Prism !== 'undefined') {
        Prism.highlightAll();
    }
});

// Navigation functionality
function initializeNavigation() {
    const navButtons = document.querySelectorAll('.nav-btn');
    
    navButtons.forEach(button => {
        button.addEventListener('click', function() {
            const targetSection = this.dataset.section;
            showSection(targetSection);
            
            // Update active nav button
            navButtons.forEach(btn => btn.classList.remove('active'));
            this.classList.add('active');
        });
    });
    
    // Hero action buttons
    const heroButtons = document.querySelectorAll('[data-section]');
    heroButtons.forEach(button => {
        if (!button.classList.contains('nav-btn')) {
            button.addEventListener('click', function() {
                const targetSection = this.dataset.section;
                showSection(targetSection);
                
                // Update nav
                navButtons.forEach(btn => btn.classList.remove('active'));
                document.querySelector(`[data-section="${targetSection}"].nav-btn`).classList.add('active');
            });
        }
    });
}

function showSection(sectionName) {
    // Hide all sections
    document.querySelectorAll('.section').forEach(section => {
        section.classList.remove('active');
    });
    
    // Show target section
    document.getElementById(sectionName).classList.add('active');
    currentSection = sectionName;
    
    // Scroll to top
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

// Code Analyzer functionality
function initializeCodeAnalyzer() {
    const codeInput = document.getElementById('codeInput');
    const analyzeBtn = document.getElementById('analyzeBtn');
    const exampleButtons = document.querySelectorAll('[data-example]');
    
    // Example code buttons
    exampleButtons.forEach(button => {
        button.addEventListener('click', function() {
            const exampleType = this.dataset.example;
            codeInput.value = codeExamples[exampleType];
            
            // Auto-analyze after loading example
            setTimeout(() => analyzeCode(), 100);
        });
    });
    
    // Analyze button
    analyzeBtn.addEventListener('click', analyzeCode);
    
    // Real-time analysis (debounced)
    let analyzeTimeout;
    codeInput.addEventListener('input', function() {
        clearTimeout(analyzeTimeout);
        analyzeTimeout = setTimeout(analyzeCode, 1000);
    });
}

function analyzeCode() {
    const codeInput = document.getElementById('codeInput');
    const resultsContainer = document.getElementById('analysisResults');
    const vulnerabilityCount = document.getElementById('vulnerabilityCount');
    
    const code = codeInput.value.trim();
    
    if (!code) {
        showEmptyResults();
        return;
    }
    
    // Simulate analysis with loading state
    showLoadingResults();
    
    setTimeout(() => {
        const vulnerabilities = detectVulnerabilities(code);
        displayAnalysisResults(vulnerabilities);
    }, 800);
}

function detectVulnerabilities(code) {
    const vulnerabilities = [];
    
    // Check for Lombok @Data annotation
    if (code.includes('@Data') && code.includes('@Entity')) {
        vulnerabilities.push({
            type: 'Lombok @Data Exposure',
            severity: 'HIGH',
            description: 'Entity class uses @Data annotation which generates setters for all fields, potentially exposing sensitive data.',
            line: findLineNumber(code, '@Data'),
            recommendation: 'Use @Getter and selective @Setter annotations instead.'
        });
    }
    
    // Check for direct entity binding
    if (code.includes('@RequestBody') && code.includes('User') && code.includes('@PostMapping')) {
        vulnerabilities.push({
            type: 'Direct Entity Binding',
            severity: 'HIGH',
            description: 'Controller method directly binds request body to entity class without DTO layer.',
            line: findLineNumber(code, '@RequestBody'),
            recommendation: 'Create DTO classes for request binding and map to entities in service layer.'
        });
    }
    
    // Check for unsafe Jackson config
    if (code.includes('fail-on-unknown-properties: false')) {
        vulnerabilities.push({
            type: 'Unsafe Jackson Configuration',
            severity: 'MEDIUM',
            description: 'Jackson deserialization allows unknown properties which can lead to mass assignment.',
            line: findLineNumber(code, 'fail-on-unknown-properties'),
            recommendation: 'Set fail-on-unknown-properties to true or implement strict property binding.'
        });
    }
    
    // Check for missing validation
    if (code.includes('@RequestBody') && !code.includes('@Valid')) {
        vulnerabilities.push({
            type: 'Missing Input Validation',
            severity: 'MEDIUM',
            description: 'Request body parameter lacks validation annotations.',
            line: findLineNumber(code, '@RequestBody'),
            recommendation: 'Add @Valid annotation and appropriate field-level validation.'
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

function showEmptyResults() {
    const resultsContainer = document.getElementById('analysisResults');
    const vulnerabilityCount = document.getElementById('vulnerabilityCount');
    
    resultsContainer.innerHTML = `
        <div class="empty-state">
            <span class="empty-icon">🔍</span>
            <p>Enter code above and click "Analyze Code" to see vulnerability detection results</p>
        </div>
    `;
    
    vulnerabilityCount.textContent = 'No vulnerabilities detected';
    vulnerabilityCount.className = 'status status--info';
}

function showLoadingResults() {
    const resultsContainer = document.getElementById('analysisResults');
    const vulnerabilityCount = document.getElementById('vulnerabilityCount');
    
    resultsContainer.innerHTML = `
        <div class="empty-state">
            <span class="empty-icon">⚡</span>
            <p class="loading">Analyzing code...</p>
        </div>
    `;
    
    vulnerabilityCount.textContent = 'Analyzing...';
    vulnerabilityCount.className = 'status status--info';
}

function displayAnalysisResults(vulnerabilities) {
    const resultsContainer = document.getElementById('analysisResults');
    const vulnerabilityCount = document.getElementById('vulnerabilityCount');
    
    if (vulnerabilities.length === 0) {
        resultsContainer.innerHTML = `
            <div class="empty-state">
                <span class="empty-icon">✅</span>
                <p>No mass assignment vulnerabilities detected in this code.</p>
            </div>
        `;
        vulnerabilityCount.textContent = 'No vulnerabilities detected';
        vulnerabilityCount.className = 'status status--success';
        return;
    }
    
    // Update counter
    const highCount = vulnerabilities.filter(v => v.severity === 'HIGH').length;
    const mediumCount = vulnerabilities.filter(v => v.severity === 'MEDIUM').length;
    
    if (highCount > 0) {
        vulnerabilityCount.textContent = `${vulnerabilities.length} vulnerabilities found (${highCount} high risk)`;
        vulnerabilityCount.className = 'status status--error';
    } else if (mediumCount > 0) {
        vulnerabilityCount.textContent = `${vulnerabilities.length} vulnerabilities found (${mediumCount} medium risk)`;
        vulnerabilityCount.className = 'status status--warning';
    } else {
        vulnerabilityCount.textContent = `${vulnerabilities.length} vulnerabilities found`;
        vulnerabilityCount.className = 'status status--info';
    }
    
    // Display results
    resultsContainer.innerHTML = vulnerabilities.map(vuln => `
        <div class="vulnerability-result">
            <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px;">
                <h5 style="margin: 0; color: ${vuln.severity === 'HIGH' ? 'var(--color-error)' : 'var(--color-warning)'};">
                    ${vuln.type}
                </h5>
                <span class="status ${vuln.severity === 'HIGH' ? 'status--error' : 'status--warning'}">${vuln.severity}</span>
            </div>
            <p style="margin-bottom: 8px;">${vuln.description}</p>
            <p style="margin-bottom: 8px; font-size: 12px;"><strong>Line ${vuln.line}</strong></p>
            <p style="margin: 0; color: var(--color-success); font-size: 12px;"><strong>Recommendation:</strong> ${vuln.recommendation}</p>
        </div>
    `).join('');
}

// Documentation functionality
function initializeDocumentation() {
    const docNavButtons = document.querySelectorAll('.docs-nav-btn');
    
    docNavButtons.forEach(button => {
        button.addEventListener('click', function() {
            const targetDoc = this.dataset.doc;
            showDocSection(targetDoc);
            
            // Update active nav button
            docNavButtons.forEach(btn => btn.classList.remove('active'));
            this.classList.add('active');
        });
    });
}

function showDocSection(docName) {
    // Hide all doc sections
    document.querySelectorAll('.doc-section').forEach(section => {
        section.classList.remove('active');
    });
    
    // Show target section
    document.getElementById(docName).classList.add('active');
    currentDoc = docName;
    
    // Re-highlight code if Prism is available
    if (typeof Prism !== 'undefined') {
        setTimeout(() => Prism.highlightAll(), 100);
    }
}

// Chart initialization
function initializeChart() {
    const ctx = document.getElementById('vulnerabilityChart');
    if (!ctx) return;
    
    vulnerabilityChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['High Risk', 'Medium Risk', 'Low Risk'],
            datasets: [{
                data: [3, 4, 1],
                backgroundColor: ['#1FB8CD', '#FFC185', '#B4413C'],
                borderWidth: 2,
                borderColor: 'var(--color-surface)'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        padding: 20,
                        color: 'var(--color-text)',
                        font: {
                            size: 14
                        }
                    }
                },
                title: {
                    display: true,
                    text: 'Vulnerability Distribution',
                    color: 'var(--color-text)',
                    font: {
                        size: 16,
                        weight: 'bold'
                    },
                    padding: 20
                }
            }
        }
    });
}

// Utility functions
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Keyboard shortcuts
document.addEventListener('keydown', function(e) {
    // Ctrl/Cmd + K to focus on code input
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        if (currentSection === 'analyzer') {
            document.getElementById('codeInput').focus();
        }
    }
    
    // Escape to clear code input
    if (e.key === 'Escape' && currentSection === 'analyzer') {
        const codeInput = document.getElementById('codeInput');
        if (document.activeElement === codeInput) {
            codeInput.blur();
        }
    }
});

// Smooth scrolling for anchor links
document.addEventListener('click', function(e) {
    if (e.target.tagName === 'A' && e.target.getAttribute('href')?.startsWith('#')) {
        e.preventDefault();
        const targetId = e.target.getAttribute('href').substring(1);
        const targetElement = document.getElementById(targetId);
        if (targetElement) {
            targetElement.scrollIntoView({ behavior: 'smooth' });
        }
    }
});

// Handle window resize for chart
window.addEventListener('resize', debounce(function() {
    if (vulnerabilityChart) {
        vulnerabilityChart.resize();
    }
}, 250));

// Auto-update timestamps
function updateTimestamps() {
    const timestampElements = document.querySelectorAll('[data-timestamp]');
    const now = new Date();
    
    timestampElements.forEach(element => {
        const timestamp = element.dataset.timestamp;
        if (timestamp === 'now') {
            element.textContent = now.toLocaleDateString('en-US', {
                year: 'numeric',
                month: 'long',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit'
            });
        }
    });
}

// Initialize timestamps
updateTimestamps();

// Copy to clipboard functionality for code examples
function addCopyButtons() {
    const codeBlocks = document.querySelectorAll('pre[class*="language-"]');
    
    codeBlocks.forEach(block => {
        const button = document.createElement('button');
        button.className = 'copy-btn';
        button.innerHTML = '📋';
        button.title = 'Copy to clipboard';
        button.style.cssText = `
            position: absolute;
            top: 8px;
            right: 8px;
            background: var(--color-secondary);
            border: 1px solid var(--color-border);
            border-radius: var(--radius-sm);
            padding: 4px 8px;
            cursor: pointer;
            font-size: 12px;
            z-index: 1;
        `;
        
        button.addEventListener('click', function() {
            const code = block.textContent;
            navigator.clipboard.writeText(code).then(() => {
                button.innerHTML = '✅';
                setTimeout(() => {
                    button.innerHTML = '📋';
                }, 1000);
            });
        });
        
        block.style.position = 'relative';
        block.appendChild(button);
    });
}

// Add copy buttons after Prism highlighting
if (typeof Prism !== 'undefined') {
    Prism.hooks.add('complete', addCopyButtons);
} else {
    // Fallback for when Prism is not available
    setTimeout(addCopyButtons, 500);
}

// Progressive enhancement for animations
function addScrollAnimations() {
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };
    
    const observer = new IntersectionObserver(function(entries) {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.opacity = '1';
                entry.target.style.transform = 'translateY(0)';
            }
        });
    }, observerOptions);
    
    // Observe cards and sections
    const animatedElements = document.querySelectorAll('.feature-card, .vulnerability-card, .stat-card');
    animatedElements.forEach(el => {
        el.style.opacity = '0';
        el.style.transform = 'translateY(20px)';
        el.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
        observer.observe(el);
    });
}

// Initialize scroll animations when page loads
setTimeout(addScrollAnimations, 100);

// Styled Folder Upload Logic
function displayAnalysisResultsHTML(vulnerabilities) {
    if (vulnerabilities.length === 0) {
        return `<div class="result-card result-card--success"><div class="result-card__body"><p>No mass assignment vulnerabilities detected in this code.</p></div></div>`;
    }
    return vulnerabilities.map(vuln => `
        <div class="result-card result-card--error">
  <div class="result-card__header">
    <span class="result-card__title">${vuln.type}</span>
    <span class="result-card__severity result-card__severity--${vuln.severity.toLowerCase()}">${vuln.severity}</span>
  </div>
  <div class="result-card__body">
    <p>${vuln.description}</p>
    <p><strong>Line ${vuln.line}</strong></p>
    <p class="result-card__recommendation"><strong>Recommendation:</strong> ${vuln.recommendation}</p>
  </div>
</div>`).join('');
}
document.addEventListener('DOMContentLoaded', function() {
    const uploadBtn = document.getElementById('uploadFolderBtn');
    const folderInput = document.getElementById('folderInput');
    if(uploadBtn && folderInput) {
        uploadBtn.addEventListener('click', function() {
            folderInput.click();
        });
        folderInput.addEventListener('change', function(event) {
            const files = Array.from(event.target.files).filter(f =>
                f.name.endsWith('.java') ||
                f.name.endsWith('.js') ||
                f.name.endsWith('.py')
            );
            const resultsContainer = document.getElementById('analysisResults');
            resultsContainer.innerHTML = '';
            files.forEach(file => {
                const reader = new FileReader();
                reader.onload = function(e) {
                    const code = e.target.result;
                    const vulnerabilities = detectVulnerabilities(code);
                    let fileResult = document.createElement('div');
                    fileResult.className = 'batch-analysis-block';
                    fileResult.innerHTML = `<h4 style="color:#fe9481;margin-bottom:10px;">${file.name}</h4>` + displayAnalysisResultsHTML(vulnerabilities);
                    resultsContainer.appendChild(fileResult);
                };
                reader.readAsText(file);
            });
        });
    }
});

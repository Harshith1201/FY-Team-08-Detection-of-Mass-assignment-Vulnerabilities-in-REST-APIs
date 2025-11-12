/**
 * Output formatters for different report types
 */

const chalk = require('chalk');
const fs = require('fs');
const path = require('path');

/**
 * Format results for console output
 */
function formatConsole(results, options = {}) {
    const { verbose = false } = options;
    
    console.log('\n' + chalk.bold.cyan('═══════════════════════════════════════════════════════'));
    console.log(chalk.bold.cyan('  SpringSecure - Mass Assignment Vulnerability Scanner'));
    console.log(chalk.bold.cyan('═══════════════════════════════════════════════════════') + '\n');

    if (results.length === 0) {
        console.log(chalk.green('✓ No vulnerabilities detected!\n'));
        return;
    }

    // Group by file
    const byFile = {};
    results.forEach(vuln => {
        if (!byFile[vuln.file]) {
            byFile[vuln.file] = [];
        }
        byFile[vuln.file].push(vuln);
    });

    // Display results
    Object.keys(byFile).forEach(file => {
        const vulns = byFile[file];
        const highCount = vulns.filter(v => v.severity === 'HIGH').length;
        const mediumCount = vulns.filter(v => v.severity === 'MEDIUM').length;
        const lowCount = vulns.filter(v => v.severity === 'LOW').length;

        console.log(chalk.bold.white(`\n📄 ${file}`));
        console.log(chalk.gray(`   Found ${vulns.length} issue(s): `) + 
            (highCount > 0 ? chalk.red(`${highCount} HIGH `) : '') +
            (mediumCount > 0 ? chalk.yellow(`${mediumCount} MEDIUM `) : '') +
            (lowCount > 0 ? chalk.blue(`${lowCount} LOW`) : ''));

        vulns.forEach((vuln, idx) => {
            const severityColor = vuln.severity === 'HIGH' ? chalk.red : 
                                 vuln.severity === 'MEDIUM' ? chalk.yellow : chalk.blue;
            
            console.log(`\n   ${idx + 1}. ${severityColor.bold(vuln.severity)} - ${chalk.bold(vuln.type)}`);
            console.log(`      ${chalk.gray('Line:')} ${vuln.line}`);
            console.log(`      ${chalk.gray('Issue:')} ${vuln.description}`);
            
            if (verbose) {
                console.log(`      ${chalk.green('Fix:')} ${vuln.recommendation}`);
            }
        });
    });

    // Summary
    const stats = {
        high: results.filter(v => v.severity === 'HIGH').length,
        medium: results.filter(v => v.severity === 'MEDIUM').length,
        low: results.filter(v => v.severity === 'LOW').length,
        total: results.length,
        files: Object.keys(byFile).length
    };

    console.log('\n' + chalk.bold.cyan('───────────────────────────────────────────────────────'));
    console.log(chalk.bold('Summary:'));
    console.log(`  Total Files Scanned: ${stats.files}`);
    console.log(`  Total Issues: ${stats.total}`);
    if (stats.high > 0) console.log(`  ${chalk.red('●')} High Severity: ${stats.high}`);
    if (stats.medium > 0) console.log(`  ${chalk.yellow('●')} Medium Severity: ${stats.medium}`);
    if (stats.low > 0) console.log(`  ${chalk.blue('●')} Low Severity: ${stats.low}`);
    console.log(chalk.bold.cyan('───────────────────────────────────────────────────────') + '\n');
}

/**
 * Format results as JSON
 */
function formatJSON(results, outputPath = null) {
    const stats = {
        high: results.filter(v => v.severity === 'HIGH').length,
        medium: results.filter(v => v.severity === 'MEDIUM').length,
        low: results.filter(v => v.severity === 'LOW').length,
        total: results.length
    };

    const output = {
        timestamp: new Date().toISOString(),
        summary: stats,
        vulnerabilities: results
    };

    const jsonString = JSON.stringify(output, null, 2);

    if (outputPath) {
        fs.writeFileSync(outputPath, jsonString);
        console.log(chalk.green(`\n✓ JSON report saved to: ${outputPath}\n`));
    } else {
        console.log(jsonString);
    }

    return output;
}

/**
 * Format results as simple text
 */
function formatText(results, outputPath = null) {
    let output = 'SpringSecure - Mass Assignment Vulnerability Report\n';
    output += '='.repeat(60) + '\n\n';
    output += `Generated: ${new Date().toISOString()}\n`;
    output += `Total Vulnerabilities: ${results.length}\n\n`;

    const byFile = {};
    results.forEach(vuln => {
        if (!byFile[vuln.file]) {
            byFile[vuln.file] = [];
        }
        byFile[vuln.file].push(vuln);
    });

    Object.keys(byFile).forEach(file => {
        output += `\nFile: ${file}\n`;
        output += '-'.repeat(60) + '\n';
        
        byFile[file].forEach((vuln, idx) => {
            output += `\n${idx + 1}. [${vuln.severity}] ${vuln.type}\n`;
            output += `   Line: ${vuln.line}\n`;
            output += `   Description: ${vuln.description}\n`;
            output += `   Recommendation: ${vuln.recommendation}\n`;
        });
    });

    if (outputPath) {
        fs.writeFileSync(outputPath, output);
        console.log(chalk.green(`\n✓ Text report saved to: ${outputPath}\n`));
    } else {
        console.log(output);
    }

    return output;
}

module.exports = {
    formatConsole,
    formatJSON,
    formatText
};


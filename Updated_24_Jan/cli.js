#!/usr/bin/env node

/**
 * SpringSecure CLI - Mass Assignment Vulnerability Scanner
 */

const { Command } = require('commander');
const chalk = require('chalk');
const path = require('path');
const { detectVulnerabilities } = require('./analyzer');
const { scanFile, scanDirectory, getPathType } = require('./scanner');
const { formatConsole, formatJSON, formatText } = require('./formatter');
const { cloneRepository, cleanupTempDir, isGitHubUrl } = require('./repo-scanner');

const program = new Command();

program
    .name('springsecure')
    .description('CLI tool for detecting mass assignment vulnerabilities in Spring Boot applications')
    .version('1.0.0');

program
    .argument('[path]', 'File or directory to scan', '.')
    .option('-o, --output <file>', 'Output file path for report')
    .option('-f, --format <type>', 'Output format: console, json, text', 'console')
    .option('-v, --verbose', 'Show detailed recommendations', false)
    .option('--json', 'Output as JSON (shorthand for -f json)')
    .option('--text', 'Output as text (shorthand for -f text)')
    .option('--fail-on-high', 'Exit with error code if high severity issues found', false)
    .option('--fail-on-medium', 'Exit with error code if medium+ severity issues found', false)
    .option('--url <url>', 'Base URL for dynamic analysis (e.g., http://localhost:8080)')
    .action(async (targetPath, options) => {
        try {
            await runScan(targetPath, options);
        } catch (error) {
            console.error(chalk.red(`\n✗ Error: ${error.message}\n`));
            process.exit(1);
        }
    });

const { verifyVulnerabilities } = require('./dynamic-scanner');

async function runScan(targetPath, options) {
    let resolvedPath = targetPath;
    let tempDir = null;
    let isRepo = false;

    // Check if it's a GitHub URL
    if (isGitHubUrl(targetPath)) {
        console.log(chalk.cyan('\n📦 Detected GitHub repository URL\n'));
        const cloneResult = await cloneRepository(targetPath);

        if (!cloneResult.success) {
            throw new Error(`Failed to clone repository: ${cloneResult.error}`);
        }

        resolvedPath = cloneResult.path;
        tempDir = cloneResult.path;
        isRepo = true;
        console.log(chalk.green('✓ Repository cloned successfully\n'));
    } else {
        // Resolve local path
        resolvedPath = path.resolve(targetPath);
        const pathType = getPathType(resolvedPath);

        if (pathType === 'not-found') {
            throw new Error(`Path not found: ${targetPath}`);
        }
    }

    // Determine format
    let format = options.format;
    if (options.json) format = 'json';
    if (options.text) format = 'text';

    console.log(chalk.cyan(`🔍 Scanning: ${resolvedPath}\n`));

    let filesToScan = [];
    const pathType = getPathType(resolvedPath);

    if (pathType === 'file') {
        filesToScan = [resolvedPath];
    } else if (pathType === 'directory') {
        const scanResult = await scanDirectory(resolvedPath);
        if (!scanResult.success) {
            if (tempDir) cleanupTempDir(tempDir);
            throw new Error(scanResult.error);
        }
        filesToScan = scanResult.files;
        console.log(chalk.gray(`Found ${scanResult.count} file(s) to analyze...\n`));
    }

    if (filesToScan.length === 0) {
        console.log(chalk.yellow('⚠ No Java or YAML files found to scan.\n'));
        return;
    }

    // Analyze files
    const allVulnerabilities = [];

    for (const file of filesToScan) {
        const fileResult = scanFile(file);
        if (!fileResult.success) {
            console.warn(chalk.yellow(`⚠ Could not read file: ${file}`));
            continue;
        }

        const vulnerabilities = detectVulnerabilities(fileResult.content, file);
        allVulnerabilities.push(...vulnerabilities);
    }

    // Dynamic Analysis Phase
    if (options.url) {
        // Run dynamic verification
        const dynamicResults = await verifyVulnerabilities(allVulnerabilities, options.url);

        // Merge results or mark verified
        // For now, we'll just update the existing vulnerability objects if they were verified
        // But since verifyVulnerabilities returns a new list of results with extra data,
        // we can potentially augment the report.

        // Let's just update the console output for now as the formatters might not handle the extra fields yet
        // In a full implementation, we'd merge dynamicValidation back into allVulnerabilities
    }

    // Format and display results
    if (format === 'json') {
        formatJSON(allVulnerabilities, options.output);
    } else if (format === 'text') {
        formatText(allVulnerabilities, options.output);
    } else {
        formatConsole(allVulnerabilities, { verbose: options.verbose });

        // If output file specified in console mode, also save JSON
        if (options.output) {
            formatJSON(allVulnerabilities, options.output);
        }
    }

    // Check exit conditions
    const highCount = allVulnerabilities.filter(v => v.severity === 'HIGH').length;
    const mediumCount = allVulnerabilities.filter(v => v.severity === 'MEDIUM').length;

    if (options.failOnHigh && highCount > 0) {
        console.error(chalk.red(`\n✗ Found ${highCount} high severity issue(s). Exiting with error.\n`));
        process.exit(1);
    }

    if (options.failOnMedium && (highCount > 0 || mediumCount > 0)) {
        console.error(chalk.red(`\n✗ Found ${highCount + mediumCount} medium+ severity issue(s). Exiting with error.\n`));
        process.exit(1);
    }

    if (allVulnerabilities.length === 0) {
        console.log(chalk.green('✓ Scan complete. No issues found!\n'));
    }

    // Cleanup temporary directory if it was a repo
    if (tempDir) {
        console.log(chalk.gray('\n🧹 Cleaning up temporary files...'));
        cleanupTempDir(tempDir);
    }
}

program.parse();


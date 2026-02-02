const axios = require('axios');
const chalk = require('chalk');

/**
 * Dynamic Scanner Module
 * Verifies static findings by sending requests to a running application instance.
 */

async function verifyVulnerabilities(vulnerabilities, baseUrl) {
    console.log(chalk.blue(`\n⚡ Starting Dynamic Analysis against ${baseUrl}...`));

    // Filter for verifiable vulnerabilities (Controllers)
    const candidates = vulnerabilities.filter(v =>
        v.type === 'Direct Entity Binding in Controller' && v.metadata && v.metadata.endpoint
    );

    if (candidates.length === 0) {
        console.log(chalk.yellow('⚠ No verifiable endpoints found in static analysis results.'));
        console.log(chalk.gray('(Dynamic analysis requires successfully detected Controller endpoints)'));
        return [];
    }

    console.log(chalk.gray(`Found ${candidates.length} candidate(s) for verification.`));

    const results = [];

    for (const issue of candidates) {
        const { endpoint, method, entity } = issue.metadata;
        const fullUrl = `${baseUrl}${endpoint}`;

        console.log(chalk.gray(`\nTesting ${method} ${fullUrl} (Entity: ${entity})...`));

        try {
            // 1. First, try to fetch the object (if GET exists) or assume we can create/update
            // This is a simplified "dumb" fuzzer approach for now

            // Craft a payload with a "sensitive" field that shouldn't be settable
            // We'll guess common sensitive fields based on the entity name or context
            const sensitivePayload = {
                isAdmin: true,
                role: 'ADMIN',
                balance: 1000000,
                id: 99999
            };

            const response = await axios({
                method: method,
                url: fullUrl,
                data: sensitivePayload,
                validateStatus: () => true // Don't throw on error status
            });

            // Analyze response
            // If the response contains our injected sensitive data, it's likely vulnerable
            const responseBody = JSON.stringify(response.data);

            let confirmed = false;
            let evidence = '';

            if (responseBody.includes('"isAdmin":true') ||
                responseBody.includes('"role":"ADMIN"') ||
                (responseBody.includes('1000000') && responseBody.includes('balance'))) {
                confirmed = true;
                evidence = 'Response reflected injected sensitive fields (Mass Assignment successful).';
            }

            results.push({
                ...issue,
                dynamicValidation: {
                    testedUrl: fullUrl,
                    status: response.status,
                    confirmed: confirmed,
                    evidence: evidence || 'No immediate evidence of mass assignment in response.'
                }
            });

            if (confirmed) {
                console.log(chalk.red(`  ✗ VULNERABILITY CONFIRMED: Allowed setting sensitive fields!`));
            } else {
                console.log(chalk.green(`  ✓ Could not verify mass assignment (Server returned allowed fields or error).`));
            }

        } catch (error) {
            console.log(chalk.yellow(`  ⚠ Connection failed or timeout: ${error.message}`));
            results.push({
                ...issue,
                dynamicValidation: {
                    testedUrl: fullUrl,
                    error: error.message
                }
            });
        }
    }

    return results;
}

module.exports = {
    verifyVulnerabilities
};

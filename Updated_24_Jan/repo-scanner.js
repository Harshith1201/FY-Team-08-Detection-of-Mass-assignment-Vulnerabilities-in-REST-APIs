/**
 * GitHub repository scanning utilities
 */

const simpleGit = require('simple-git');
const fs = require('fs');
const path = require('path');
const os = require('os');

/**
 * Clone a GitHub repository to a temporary directory
 */
async function cloneRepository(repoUrl) {
    const tempDir = path.join(os.tmpdir(), `springsecure-${Date.now()}`);
    
    try {
        console.log(`Cloning repository: ${repoUrl}`);
        console.log(`Temporary directory: ${tempDir}`);
        
        const git = simpleGit();
        await git.clone(repoUrl, tempDir);
        
        return {
            success: true,
            path: tempDir,
            url: repoUrl
        };
    } catch (error) {
        return {
            success: false,
            error: error.message
        };
    }
}

/**
 * Clean up temporary directory
 */
function cleanupTempDir(dirPath) {
    try {
        if (fs.existsSync(dirPath)) {
            fs.rmSync(dirPath, { recursive: true, force: true });
            return true;
        }
    } catch (error) {
        console.warn(`Warning: Could not clean up ${dirPath}: ${error.message}`);
        return false;
    }
}

/**
 * Parse GitHub URL to extract owner and repo name
 */
function parseGitHubUrl(url) {
    // Support various GitHub URL formats
    const patterns = [
        /github\.com\/([^\/]+)\/([^\/\.]+)/,  // https://github.com/owner/repo
        /github\.com:([^\/]+)\/([^\/\.]+)/,   // git@github.com:owner/repo
    ];
    
    for (const pattern of patterns) {
        const match = url.match(pattern);
        if (match) {
            return {
                owner: match[1],
                repo: match[2].replace(/\.git$/, ''),
                valid: true
            };
        }
    }
    
    return { valid: false };
}

/**
 * Check if URL is a GitHub repository
 */
function isGitHubUrl(url) {
    return url.includes('github.com');
}

module.exports = {
    cloneRepository,
    cleanupTempDir,
    parseGitHubUrl,
    isGitHubUrl
};


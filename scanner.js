/**
 * File and directory scanning utilities
 */

const fs = require('fs');
const path = require('path');
const { glob } = require('glob');

/**
 * Scan a single file
 */
function scanFile(filePath) {
    try {
        const content = fs.readFileSync(filePath, 'utf-8');
        return {
            path: filePath,
            content: content,
            success: true
        };
    } catch (error) {
        return {
            path: filePath,
            error: error.message,
            success: false
        };
    }
}

/**
 * Scan a directory recursively for Java files
 */
async function scanDirectory(dirPath, options = {}) {
    const {
        extensions = ['.java', '.yml', '.yaml'],
        exclude = ['node_modules', 'target', 'build', '.git']
    } = options;

    try {
        // Build glob pattern
        const patterns = extensions.map(ext => `**/*${ext}`);
        const ignorePatterns = exclude.map(dir => `**/${dir}/**`);

        const files = [];
        
        for (const pattern of patterns) {
            const matches = await glob(pattern, {
                cwd: dirPath,
                ignore: ignorePatterns,
                absolute: true,
                nodir: true
            });
            files.push(...matches);
        }

        return {
            files: files,
            count: files.length,
            success: true
        };
    } catch (error) {
        return {
            error: error.message,
            success: false
        };
    }
}

/**
 * Check if path is a file or directory
 */
function getPathType(targetPath) {
    try {
        const stats = fs.statSync(targetPath);
        if (stats.isFile()) {
            return 'file';
        } else if (stats.isDirectory()) {
            return 'directory';
        }
        return 'unknown';
    } catch (error) {
        return 'not-found';
    }
}

/**
 * Validate file extension
 */
function isValidFile(filePath, extensions = ['.java', '.yml', '.yaml']) {
    const ext = path.extname(filePath).toLowerCase();
    return extensions.includes(ext);
}

module.exports = {
    scanFile,
    scanDirectory,
    getPathType,
    isValidFile
};


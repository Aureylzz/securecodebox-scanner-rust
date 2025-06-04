#!/usr/bin/env node

const fs = require('fs');

// Parse command line arguments OR use environment variable
const scanResultsFile = process.argv[2] || process.env.SCAN_RESULTS_FILE;

if (!scanResultsFile) {
    console.error('Usage: parser.js <scan-results-file>');
    console.error('Or set SCAN_RESULTS_FILE environment variable');
    process.exit(1);
}

console.error(`INFO: Processing scan results from: ${scanResultsFile}`);

// Read and parse the cargo-audit JSON output
let scanResults;
try {
    const rawData = fs.readFileSync(scanResultsFile, 'utf8');
    console.error(`DEBUG: Read ${rawData.length} bytes from file`);
    scanResults = JSON.parse(rawData);
    console.error(`DEBUG: Successfully parsed JSON`);
} catch (error) {
    console.error(`Error reading scan results: ${error.message}`);
    // Output empty findings array for SecureCodeBox
    console.log(JSON.stringify([]));
    process.exit(0); // Exit successfully even if parsing fails
}

// Transform cargo-audit findings to SecureCodeBox format
const findings = [];

console.error(`DEBUG: Checking for vulnerabilities...`);
console.error(`DEBUG: scanResults.vulnerabilities exists: ${!!scanResults.vulnerabilities}`);
console.error(`DEBUG: scanResults.vulnerabilities.count: ${scanResults.vulnerabilities?.count}`);

// Check if we have vulnerabilities in the scan results
if (scanResults.vulnerabilities && scanResults.vulnerabilities.list && Array.isArray(scanResults.vulnerabilities.list)) {
    console.error(`DEBUG: Processing ${scanResults.vulnerabilities.list.length} vulnerabilities`);
    
    scanResults.vulnerabilities.list.forEach((vuln, index) => {
        console.error(`DEBUG: Processing vulnerability ${index + 1}`);
        
        // Extract the advisory information
        const advisory = vuln.advisory;
        if (!advisory) {
            console.error(`DEBUG: Skipping vulnerability ${index + 1} - no advisory found`);
            return;
        }
        
        console.error(`DEBUG: Advisory ID: ${advisory.id}`);
        console.error(`DEBUG: Advisory title: ${advisory.title}`);
        
        // Determine severity from CVSS score
        let severity = 'MEDIUM'; // Default severity
        if (advisory.cvss) {
            // CVSS format: "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
            // Check for High impact values
            if (advisory.cvss.includes('/A:H') || advisory.cvss.includes('/C:H') || advisory.cvss.includes('/I:H')) {
                severity = 'HIGH';
            } else if (advisory.cvss.includes('/A:L') || advisory.cvss.includes('/C:L') || advisory.cvss.includes('/I:L')) {
                severity = 'LOW';
            }
            console.error(`DEBUG: Determined severity: ${severity}`);
        }
        
        // Build the finding object
        const finding = {
            name: `${advisory.id}: ${advisory.title}`,
            description: advisory.description || 'No description provided',
            category: 'Vulnerable Dependency',
            severity: severity,
            osi_layer: 'APPLICATION',
            attributes: {
                rustsec_id: advisory.id,
                package: vuln.package?.name || 'Unknown',
                affected_versions: vuln.versions?.patched?.join(', ') || 'Unknown',
                installed_version: vuln.package?.version || 'Unknown',
                date: advisory.date,
                url: advisory.url || `https://rustsec.org/advisories/${advisory.id}`,
                cve: Array.isArray(advisory.aliases) ? advisory.aliases.filter(alias => alias.startsWith('CVE')).join(', ') : null,
                cvss: advisory.cvss || null,
                categories: Array.isArray(advisory.categories) ? advisory.categories.join(', ') : null,
                keywords: Array.isArray(advisory.keywords) ? advisory.keywords.join(', ') : null,
                patched_versions: vuln.versions?.patched?.join(', ') || null,
                unaffected_versions: vuln.versions?.unaffected?.join(', ') || null
            },
            location: vuln.package ? `${vuln.package.name}@${vuln.package.version}` : null
        };
        
        // Clean up null values from attributes
        Object.keys(finding.attributes).forEach(key => {
            if (finding.attributes[key] === null || finding.attributes[key] === undefined) {
                delete finding.attributes[key];
            }
        });
        
        console.error(`DEBUG: Created finding: ${finding.name}`);
        findings.push(finding);
    });
} else {
    console.error('DEBUG: No vulnerabilities.list found in scan results');
}

// Handle warnings as separate findings (if any)
if (scanResults.warnings && Array.isArray(scanResults.warnings)) {
    console.error(`DEBUG: Processing ${scanResults.warnings.length} warnings`);
    scanResults.warnings.forEach((warning) => {
        const finding = {
            name: 'Cargo Audit Warning',
            description: warning.message || warning,
            category: 'Security Warning',
            severity: 'LOW',
            osi_layer: 'APPLICATION',
            attributes: {
                warning_type: warning.kind || 'general'
            }
        };
        findings.push(finding);
    });
}

console.error(`DEBUG: Total findings created: ${findings.length}`);

// Determine output location based on environment
const outputFile = process.env.FINDINGS_FILE || '/home/securecodebox/findings.json';

// Write findings to the expected location for SecureCodeBox
if (outputFile === '/dev/stdout' || outputFile === '-') {
    // Direct stdout output
    console.log(JSON.stringify(findings, null, 2));
} else {
    // Write to file
    try {
        fs.writeFileSync(outputFile, JSON.stringify(findings, null, 2));
        console.error(`INFO: Findings written to ${outputFile}`);
        // Also output to stdout for debugging
        console.log(JSON.stringify(findings, null, 2));
    } catch (error) {
        console.error(`ERROR: Failed to write findings to ${outputFile}: ${error.message}`);
        // Fallback to stdout
        console.log(JSON.stringify(findings, null, 2));
    }
}
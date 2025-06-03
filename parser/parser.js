#!/usr/bin/env node

const fs = require('fs');

// Parse command line arguments
const scanResultsFile = process.argv[2];

if (!scanResultsFile) {
    console.error('Usage: parser.js <scan-results-file>');
    process.exit(1);
}

// Read and parse the cargo-audit JSON output
let scanResults;
try {
    const rawData = fs.readFileSync(scanResultsFile, 'utf8');
    console.error(`DEBUG: Read ${rawData.length} bytes from file`);
    scanResults = JSON.parse(rawData);
    console.error(`DEBUG: Successfully parsed JSON`);
} catch (error) {
    console.error(`Error reading scan results: ${error.message}`);
    process.exit(1);
}

// Transform cargo-audit findings to SecureCodeBox format
const findings = [];

console.error(`DEBUG: Checking for vulnerabilities...`);
console.error(`DEBUG: scanResults.vulnerabilities exists: ${!!scanResults.vulnerabilities}`);
console.error(`DEBUG: scanResults.vulnerabilities.count: ${scanResults.vulnerabilities?.count}`);
console.error(`DEBUG: scanResults.vulnerabilities.list exists: ${!!scanResults.vulnerabilities?.list}`);
console.error(`DEBUG: scanResults.vulnerabilities.list is array: ${Array.isArray(scanResults.vulnerabilities?.list)}`);
console.error(`DEBUG: scanResults.vulnerabilities.list length: ${scanResults.vulnerabilities?.list?.length}`);

// Check if we have vulnerabilities in the scan results
if (scanResults.vulnerabilities && scanResults.vulnerabilities.list && Array.isArray(scanResults.vulnerabilities.list)) {
    console.error(`DEBUG: Processing ${scanResults.vulnerabilities.list.length} vulnerabilities`);
    
    scanResults.vulnerabilities.list.forEach((vuln, index) => {
        console.error(`DEBUG: Processing vulnerability ${index + 1}`);
        console.error(`DEBUG: vuln.advisory exists: ${!!vuln.advisory}`);
        console.error(`DEBUG: vuln.package exists: ${!!vuln.package}`);
        
        // Extract the advisory information
        const advisory = vuln.advisory;
        if (!advisory) {
            console.error(`DEBUG: Skipping vulnerability ${index + 1} - no advisory found`);
            return;
        }
        
        console.error(`DEBUG: Advisory ID: ${advisory.id}`);
        console.error(`DEBUG: Advisory title: ${advisory.title}`);
        console.error(`DEBUG: Advisory CVSS: ${advisory.cvss}`);
        
        // Determine severity from CVSS score
        let severity = 'MEDIUM'; // Default severity
        if (advisory.cvss) {
            console.error(`DEBUG: Parsing CVSS: ${advisory.cvss}`);
            // CVSS format: "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
            // We need to calculate the score from these values or look for a score
            // For now, let's use a simple mapping based on the impact values
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
if (scanResults.warnings) {
    console.error(`DEBUG: Processing warnings...`);
    // In cargo-audit output, warnings might be an object or array
    // Let's handle both cases
    if (Array.isArray(scanResults.warnings)) {
        console.error(`DEBUG: Warnings is array with ${scanResults.warnings.length} items`);
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
    } else if (typeof scanResults.warnings === 'object') {
        console.error(`DEBUG: Warnings is object`);
        // Warnings might be an empty object or have properties
        // For now, we'll skip empty warning objects
    }
}

console.error(`DEBUG: Total findings created: ${findings.length}`);

// Output the findings in SecureCodeBox format
console.log(JSON.stringify(findings, null, 2));
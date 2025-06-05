#!/usr/bin/env node
/**
 * SecureCodeBox Parser for Rust Security Scanner
 * 
 * This script transforms cargo-audit JSON output into SecureCodeBox findings format.
 * It extracts vulnerability information and maps it to the standardized finding structure
 * that SecureCodeBox expects.
 */

const fs = require('fs');
const http = require('http');
const https = require('https');
const { URL } = require('url');

// Parse command line arguments OR use environment variable
// SecureCodeBox can provide the path either way
const scanResultsLocation = process.argv[2] || process.env.SCAN_RESULTS_FILE;

if (!scanResultsLocation) {
    console.error('Usage: parser.js <scan-results-file-or-url>');
    console.error('Or set SCAN_RESULTS_FILE environment variable');
    process.exit(1);
}

console.error(`INFO: Processing scan results from: ${scanResultsLocation}`);

// Function to download content from a URL
async function downloadFromUrl(urlString) {
    return new Promise((resolve, reject) => {
        try {
            const parsedUrl = new URL(urlString);
            const client = parsedUrl.protocol === 'https:' ? https : http;
            
            console.error(`DEBUG: Downloading from ${parsedUrl.protocol}//${parsedUrl.host}${parsedUrl.pathname}`);
            
            const request = client.get(urlString, (response) => {
                if (response.statusCode !== 200) {
                    reject(new Error(`Failed to download: HTTP ${response.statusCode}`));
                    return;
                }
                
                let data = '';
                response.on('data', (chunk) => {
                    data += chunk;
                });
                
                response.on('end', () => {
                    console.error(`DEBUG: Downloaded ${data.length} bytes`);
                    resolve(data);
                });
            });
            
            request.on('error', (error) => {
                reject(error);
            });
            
            // Set a timeout to prevent hanging
            request.setTimeout(30000, () => {
                request.destroy();
                reject(new Error('Download timeout'));
            });
            
        } catch (error) {
            reject(error);
        }
    });
}

// Function to check if input is a URL
function isUrl(string) {
    try {
        new URL(string);
        return true;
    } catch {
        return false;
    }
}

// Main async function to handle both files and URLs
async function main() {
    let rawData;
    
    try {
        if (isUrl(scanResultsLocation)) {
            // It's a URL - download the content
            console.error('DEBUG: Detected URL input, downloading scan results...');
            rawData = await downloadFromUrl(scanResultsLocation);
        } else {
            // It's a file path - read it directly
            console.error('DEBUG: Detected file path input, reading from disk...');
            rawData = fs.readFileSync(scanResultsLocation, 'utf8');
            console.error(`DEBUG: Read ${rawData.length} bytes from file`);
        }
        
        // Parse the JSON content
        const scanResults = JSON.parse(rawData);
        console.error(`DEBUG: Successfully parsed JSON`);
        
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
                
                // Extract the advisory information - this contains all the vulnerability details
                const advisory = vuln.advisory;
                if (!advisory) {
                    console.error(`DEBUG: Skipping vulnerability ${index + 1} - no advisory found`);
                    return;
                }
                
                console.error(`DEBUG: Advisory ID: ${advisory.id}`);
                console.error(`DEBUG: Advisory title: ${advisory.title}`);
                
                // Determine severity from CVSS score
                // CVSS format: "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
                // We check for High impact values in Confidentiality, Integrity, or Availability
                let severity = 'MEDIUM'; // Default severity
                if (advisory.cvss) {
                    // If any of the CIA triad has High impact, consider it HIGH severity
                    if (advisory.cvss.includes('/A:H') || advisory.cvss.includes('/C:H') || advisory.cvss.includes('/I:H')) {
                        severity = 'HIGH';
                    } else if (advisory.cvss.includes('/A:L') || advisory.cvss.includes('/C:L') || advisory.cvss.includes('/I:L')) {
                        severity = 'LOW';
                    }
                    console.error(`DEBUG: Determined severity: ${severity}`);
                }
                
                // Build the finding object in SecureCodeBox format
                const finding = {
                    // Combine the advisory ID and title for a descriptive name
                    name: `${advisory.id}: ${advisory.title}`,
                    
                    // Use the full description if available
                    description: advisory.description || 'No description provided',
                    
                    // Category helps group similar findings
                    category: 'Vulnerable Dependency',
                    
                    // Severity determined from CVSS score
                    severity: severity,
                    
                    // OSI layer - application layer for dependency vulnerabilities
                    osi_layer: 'APPLICATION',
                    
                    // Additional attributes provide detailed information
                    attributes: {
                        rustsec_id: advisory.id,
                        package: vuln.package?.name || 'Unknown',
                        installed_version: vuln.package?.version || 'Unknown',
                        date: advisory.date,
                        url: advisory.url || `https://rustsec.org/advisories/${advisory.id}`,
                        
                        // Include CVE if available (filter for CVE format)
                        cve: Array.isArray(advisory.aliases) 
                            ? advisory.aliases.filter(alias => alias.startsWith('CVE')).join(', ') 
                            : null,
                        
                        // Include full CVSS string for reference
                        cvss: advisory.cvss || null,
                        
                        // Categories help understand the type of vulnerability
                        categories: Array.isArray(advisory.categories) 
                            ? advisory.categories.join(', ') 
                            : null,
                        
                        // Keywords provide additional context
                        keywords: Array.isArray(advisory.keywords) 
                            ? advisory.keywords.join(', ') 
                            : null,
                        
                        // Version information helps with remediation
                        patched_versions: vuln.versions?.patched?.join(', ') || null,
                        unaffected_versions: vuln.versions?.unaffected?.join(', ') || null
                    },
                    
                    // Location helps identify where the vulnerability exists
                    location: vuln.package ? `${vuln.package.name}@${vuln.package.version}` : null
                };
                
                // Clean up null values from attributes to keep output tidy
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
        // Warnings might indicate issues with the scan itself
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
        // SecureCodeBox may specify where to write findings
        const outputFile = process.env.FINDINGS_FILE || '/home/securecodebox/findings.json';
        
        // Write findings to the expected location for SecureCodeBox
        if (outputFile === '/dev/stdout' || outputFile === '-') {
            // Direct stdout output for testing
            console.log(JSON.stringify(findings, null, 2));
        } else {
            // Write to file for SecureCodeBox
            try {
                fs.writeFileSync(outputFile, JSON.stringify(findings, null, 2));
                console.error(`INFO: Findings written to ${outputFile}`);
                // Also output to stdout for debugging
                console.log(JSON.stringify(findings, null, 2));
            } catch (error) {
                console.error(`ERROR: Failed to write findings to ${outputFile}: ${error.message}`);
                // Fallback to stdout if file write fails
                console.log(JSON.stringify(findings, null, 2));
            }
        }
        
    } catch (error) {
        console.error(`Error processing scan results: ${error.message}`);
        // Output empty findings array for SecureCodeBox
        // This ensures the parser doesn't crash the entire scan process
        console.log(JSON.stringify([]));
        process.exit(0); // Exit successfully even if parsing fails
    }
}

// Run the main function
main();
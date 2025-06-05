#!/usr/bin/env node
/**
 * SecureCodeBox Enhanced Parser for Rust Multi-Tool Scanner
 * 
 * This script transforms output from multiple Rust security tools into SecureCodeBox findings:
 * - cargo-audit: Security vulnerabilities
 * - cargo-deny: License compliance and dependency issues
 * - cargo-geiger: Unsafe code usage
 * - clippy: Code quality issues
 */

const fs = require('fs');
const http = require('http');
const https = require('https');
const { URL } = require('url');

// Parse command line arguments OR use environment variable
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

// Process cargo-audit results
function processCargoAudit(auditData, findings) {
    if (!auditData || auditData.warning) {
        console.error('DEBUG: Skipping cargo-audit - no data or warning present');
        return;
    }
    
    if (auditData.vulnerabilities && auditData.vulnerabilities.list) {
        console.error(`DEBUG: Processing ${auditData.vulnerabilities.list.length} vulnerabilities from cargo-audit`);
        
        auditData.vulnerabilities.list.forEach((vuln) => {
            const advisory = vuln.advisory;
            if (!advisory) return;
            
            let severity = 'MEDIUM';
            if (advisory.cvss) {
                if (advisory.cvss.includes('/A:H') || advisory.cvss.includes('/C:H') || advisory.cvss.includes('/I:H')) {
                    severity = 'HIGH';
                } else if (advisory.cvss.includes('/A:L') || advisory.cvss.includes('/C:L') || advisory.cvss.includes('/I:L')) {
                    severity = 'LOW';
                }
            }
            
            const finding = {
                name: `${advisory.id}: ${advisory.title}`,
                description: advisory.description || 'No description provided',
                category: 'Vulnerable Dependency',
                severity: severity,
                osi_layer: 'APPLICATION',
                scanner: 'cargo-audit',
                attributes: {
                    rustsec_id: advisory.id,
                    package: vuln.package?.name || 'Unknown',
                    installed_version: vuln.package?.version || 'Unknown',
                    date: advisory.date,
                    url: advisory.url || `https://rustsec.org/advisories/${advisory.id}`,
                    cve: Array.isArray(advisory.aliases) 
                        ? advisory.aliases.filter(alias => alias.startsWith('CVE')).join(', ') 
                        : null,
                    cvss: advisory.cvss || null,
                    patched_versions: vuln.versions?.patched?.join(', ') || null,
                    unaffected_versions: vuln.versions?.unaffected?.join(', ') || null
                },
                location: vuln.package ? `${vuln.package.name}@${vuln.package.version}` : null
            };
            
            // Clean up null values
            Object.keys(finding.attributes).forEach(key => {
                if (finding.attributes[key] === null || finding.attributes[key] === undefined) {
                    delete finding.attributes[key];
                }
            });
            
            findings.push(finding);
        });
    }
}

// Process cargo-deny results
function processCargoGeny(denyData, findings) {
    if (!denyData || denyData.warning) {
        console.error('DEBUG: Skipping cargo-deny - no data or warning present');
        return;
    }
    
    // Handle JSON format output
    if (Array.isArray(denyData)) {
        console.error(`DEBUG: Processing ${denyData.length} issues from cargo-deny`);
        
        denyData.forEach((issue) => {
            // Map cargo-deny severity to SecureCodeBox severity
            let severity = 'LOW';
            if (issue.severity === 'error') severity = 'HIGH';
            else if (issue.severity === 'warning') severity = 'MEDIUM';
            
            const finding = {
                name: `cargo-deny: ${issue.type || 'Issue'} - ${issue.message || 'Unknown issue'}`,
                description: issue.message || 'No description provided',
                category: mapDenyCategory(issue.type),
                severity: severity,
                osi_layer: 'APPLICATION',
                scanner: 'cargo-deny',
                attributes: {
                    check_type: issue.type,
                    severity: issue.severity,
                    code: issue.code
                }
            };
            
            if (issue.labels) {
                finding.location = issue.labels.map(l => l.span.file).join(', ');
            }
            
            findings.push(finding);
        });
    } else if (denyData.output) {
        // Handle text format - create a single finding
        const textOutput = denyData.output;
        const hasErrors = textOutput.includes('error:');
        const hasWarnings = textOutput.includes('warning:');
        
        if (hasErrors || hasWarnings) {
            findings.push({
                name: 'cargo-deny: License and dependency check issues found',
                description: 'cargo-deny detected issues. Run cargo-deny locally for details.',
                category: 'Dependency Compliance',
                severity: hasErrors ? 'HIGH' : 'MEDIUM',
                osi_layer: 'APPLICATION',
                scanner: 'cargo-deny',
                attributes: {
                    has_errors: hasErrors,
                    has_warnings: hasWarnings,
                    summary: textOutput.substring(0, 500) + '...'
                }
            });
        }
    }
}

// Helper function to map cargo-deny issue types to categories
function mapDenyCategory(type) {
    const categoryMap = {
        'banned': 'Banned Dependency',
        'denied': 'Denied Dependency',
        'license': 'License Compliance',
        'duplicate': 'Duplicate Dependencies',
        'source': 'Untrusted Source',
        'advisory': 'Security Advisory'
    };
    return categoryMap[type] || 'Dependency Issue';
}

// Process cargo-geiger results
function processCargoGeiger(geigerData, findings) {
    if (!geigerData || geigerData.warning) {
        console.error('DEBUG: Skipping cargo-geiger - no data or warning present');
        return;
    }
    
    const unsafeUsed = geigerData.unsafe_code_used || 0;
    const unsafeTotal = geigerData.unsafe_code_total || 0;
    
    console.error(`DEBUG: cargo-geiger found ${unsafeUsed}/${unsafeTotal} unsafe code usages`);
    
    // Only create a finding if unsafe code is actually used
    if (unsafeUsed > 0) {
        const severity = unsafeUsed > 50 ? 'HIGH' : (unsafeUsed > 10 ? 'MEDIUM' : 'LOW');
        
        findings.push({
            name: `Unsafe Code Usage Detected: ${unsafeUsed} occurrences`,
            description: `This project uses unsafe Rust code in ${unsafeUsed} places. Unsafe code bypasses Rust's memory safety guarantees and should be carefully reviewed.`,
            category: 'Code Safety',
            severity: severity,
            osi_layer: 'APPLICATION',
            scanner: 'cargo-geiger',
            attributes: {
                unsafe_code_used: unsafeUsed,
                unsafe_code_total: unsafeTotal,
                unsafe_percentage: unsafeTotal > 0 ? Math.round((unsafeUsed / unsafeTotal) * 100) : 0
            }
        });
    }
}

// Process clippy results
function processClippy(clippyData, findings) {
    if (!clippyData || clippyData.warning) {
        console.error('DEBUG: Skipping clippy - no data or warning present');
        return;
    }
    
    if (clippyData.messages && Array.isArray(clippyData.messages)) {
        console.error(`DEBUG: Processing ${clippyData.messages.length} messages from clippy`);
        
        // Group clippy warnings by lint name
        const lintGroups = {};
        
        clippyData.messages.forEach((msg) => {
            if (msg.message && msg.message.code) {
                const lintName = msg.message.code.code;
                if (!lintGroups[lintName]) {
                    lintGroups[lintName] = {
                        name: lintName,
                        level: msg.message.level,
                        count: 0,
                        locations: [],
                        firstMessage: msg.message.message
                    };
                }
                
                lintGroups[lintName].count++;
                if (msg.message.spans && msg.message.spans.length > 0) {
                    const span = msg.message.spans[0];
                    lintGroups[lintName].locations.push(`${span.file_name}:${span.line_start}`);
                }
            }
        });
        
        // Create findings for each lint type
        Object.values(lintGroups).forEach((lint) => {
            // Map clippy levels to SecureCodeBox severity
            let severity = 'LOW';
            if (lint.level === 'error') severity = 'HIGH';
            else if (lint.level === 'warning' && lint.count > 5) severity = 'MEDIUM';
            
            const finding = {
                name: `Clippy: ${lint.name} (${lint.count} occurrence${lint.count > 1 ? 's' : ''})`,
                description: lint.firstMessage || `Clippy lint ${lint.name} triggered ${lint.count} times`,
                category: 'Code Quality',
                severity: severity,
                osi_layer: 'APPLICATION',
                scanner: 'clippy',
                attributes: {
                    lint_name: lint.name,
                    lint_level: lint.level,
                    occurrence_count: lint.count,
                    sample_locations: lint.locations.slice(0, 5).join(', ')
                }
            };
            
            if (lint.locations.length > 0) {
                finding.location = lint.locations[0];
            }
            
            findings.push(finding);
        });
    }
}

// Main async function
async function main() {
    let rawData;
    
    try {
        if (isUrl(scanResultsLocation)) {
            console.error('DEBUG: Detected URL input, downloading scan results...');
            rawData = await downloadFromUrl(scanResultsLocation);
        } else {
            console.error('DEBUG: Detected file path input, reading from disk...');
            rawData = fs.readFileSync(scanResultsLocation, 'utf8');
        }
        
        const scanResults = JSON.parse(rawData);
        console.error(`DEBUG: Successfully parsed JSON for scan type: ${scanResults.scan_type}`);
        
        const findings = [];
        
        // Process results from each tool
        if (scanResults.cargo_audit) {
            processCargoAudit(scanResults.cargo_audit, findings);
        }
        
        if (scanResults.cargo_deny) {
            processCargoGeny(scanResults.cargo_deny, findings);
        }
        
        if (scanResults.cargo_geiger) {
            processCargoGeiger(scanResults.cargo_geiger, findings);
        }
        
        if (scanResults.clippy) {
            processClippy(scanResults.clippy, findings);
        }
        
        console.error(`DEBUG: Total findings created: ${findings.length}`);
        
        // Determine output location
        const outputFile = process.env.FINDINGS_FILE || '/home/securecodebox/findings.json';
        
        // Write findings
        if (outputFile === '/dev/stdout' || outputFile === '-') {
            console.log(JSON.stringify(findings, null, 2));
        } else {
            try {
                fs.writeFileSync(outputFile, JSON.stringify(findings, null, 2));
                console.error(`INFO: Findings written to ${outputFile}`);
                console.log(JSON.stringify(findings, null, 2));
            } catch (error) {
                console.error(`ERROR: Failed to write findings to ${outputFile}: ${error.message}`);
                console.log(JSON.stringify(findings, null, 2));
            }
        }
        
    } catch (error) {
        console.error(`Error processing scan results: ${error.message}`);
        console.log(JSON.stringify([]));
        process.exit(0);
    }
}

// Run the main function
main();
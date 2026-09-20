/**
 * Arbitrum Nitro / EVM AST & Heuristic Vulnerability Detector
 */
export function detectArbitrumVulnerabilities(code, filename = 'Contract.sol') {
  const findings = [];
  const lines = code.split('\n');

  const hasReentrancyGuard = code.includes('ReentrancyGuard') || code.includes('nonReentrant');

  lines.forEach((line, index) => {
    const lineNum = index + 1;
    const trimmed = line.trim();

    // 1. Deteksi Missing Access Control pada fungsi kritis
    if (
      trimmed.startsWith('function') &&
      (trimmed.includes('withdraw') || trimmed.includes('setTreasury') || trimmed.includes('emergency')) &&
      !trimmed.includes('internal') &&
      !trimmed.includes('private')
    ) {
      // Jika fungsi ditujukan untuk publik/vendor sendiri, lewati jika bukan fungsi admin darurat
      const isAdminOnly = trimmed.includes('emergency') || trimmed.includes('setTreasury');
      const hasAccessModifier = trimmed.includes('onlyOwner') || trimmed.includes('onlyRole');

      if (isAdminOnly && !hasAccessModifier) {
        findings.push({
          id: 'AEGIS-ARB-001',
          severity: 'CRITICAL',
          title: 'Missing Access Control on Critical Function',
          chain: 'arbitrum',
          cwe: 'CWE-284',
          line: lineNum,
          description: `Critical administration function '${trimmed}' is exposed publicly without 'onlyOwner' or role-based modifier.`,
          remediation: "Add an explicit access modifier such as 'onlyOwner' or OpenZeppelin AccessControl 'onlyRole(ADMIN_ROLE)'.",
          diff: {
            file: filename,
            removed: [`- Line ${lineNum}: ${trimmed}`],
            added: [`+ Fix: ${trimmed.replace('{', 'onlyOwner {')}`]
          }
        });
      }
    }

    // 2. Deteksi Reentrancy (Hanya terpicu jika TIDAK ada ReentrancyGuard/nonReentrant)
    if (trimmed.includes('.call{value:') || trimmed.includes('.call{value :')) {
      if (!hasReentrancyGuard) {
        findings.push({
          id: 'AEGIS-ARB-002',
          severity: 'CRITICAL',
          title: 'Potential Reentrancy Without Guard',
          chain: 'arbitrum',
          cwe: 'SWC-107',
          line: lineNum,
          description: `External transfer call at line ${lineNum} is invoked without ReentrancyGuard protection.`,
          remediation: 'Apply OpenZeppelin ReentrancyGuard nonReentrant modifier to the calling function and ensure state is updated before external calls.',
          diff: {
            file: filename,
            removed: [`- Line ${lineNum}: ${trimmed}`],
            added: [
              `+ // Ensure state update occurs before:`,
              `+ Line ${lineNum}: ${trimmed}`
            ]
          }
        });
      }
    }
  });

  return findings;
}
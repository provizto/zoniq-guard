/**
 * Arbitrum Nitro / EVM AST & Heuristic Vulnerability Detector
 */
function analyzeSolidityCode(code, filename = 'Contract.sol') {
  if (!code || typeof code !== 'string') {
    return {
      success: false,
      error: 'Invalid source code input.',
      issues: []
    };
  }

  const issues = [];
  const lines = code.split('\n');
  const hasReentrancyGuard = code.includes('ReentrancyGuard') || code.includes('nonReentrant');

  lines.forEach((line, index) => {
    const lineNum = index + 1;
    const trimmed = line.trim();

    // 1. Missing Access Control on critical administrative functions
    if (
      trimmed.startsWith('function') &&
      (trimmed.includes('withdraw') || trimmed.includes('setTreasury') || trimmed.includes('emergency')) &&
      !trimmed.includes('internal') &&
      !trimmed.includes('private')
    ) {
      const isAdminOnly = trimmed.includes('emergency') || trimmed.includes('setTreasury');
      const hasAccessModifier = trimmed.includes('onlyOwner') || trimmed.includes('onlyRole');

      if (isAdminOnly && !hasAccessModifier) {
        issues.push({
          id: 'AEGIS-ARB-001',
          severity: 'CRITICAL',
          title: 'Missing Access Control on Critical Function',
          chain: 'arbitrum',
          cwe: 'CWE-284',
          line: lineNum,
          description: `Critical administration function '${trimmed}' is exposed without 'onlyOwner' or role-based modifier.`,
          remediation: "Add an explicit access modifier such as 'onlyOwner' or OpenZeppelin 'onlyRole(ADMIN_ROLE)'.",
          diff: {
            file: filename,
            removed: [`- Line ${lineNum}: ${trimmed}`],
            added: [`+ Fix: ${trimmed.replace('{', 'onlyOwner {')}`]
          }
        });
      }
    }

    // 2. Reentrancy Vulnerability (triggers only if ReentrancyGuard is absent)
    if (trimmed.includes('.call{value:') || trimmed.includes('.call{value :')) {
      if (!hasReentrancyGuard) {
        issues.push({
          id: 'AEGIS-ARB-002',
          severity: 'CRITICAL',
          title: 'Potential Reentrancy Without Guard',
          chain: 'arbitrum',
          cwe: 'SWC-107',
          line: lineNum,
          description: `External transfer call at line ${lineNum} is invoked without ReentrancyGuard protection.`,
          remediation: 'Apply OpenZeppelin ReentrancyGuard nonReentrant modifier and execute state updates before external calls.',
          diff: {
            file: filename,
            removed: [`- Line ${lineNum}: ${trimmed}`],
            added: [
              `+ // Enforce nonReentrant and update state prior to call:`,
              `+ Line ${lineNum}: ${trimmed}`
            ]
          }
        });
      }
    }
  });

  return {
    success: true,
    error: null,
    totalIssues: issues.length,
    issues: issues
  };
}

module.exports = {
  analyzeSolidityCode
};
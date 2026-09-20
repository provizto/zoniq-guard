// packages/engine-arbitrum/src/detector.js

function analyzeSolidityCode(code) {
  const issues = [];
  if (!code || typeof code !== 'string') {
    return { success: false, totalIssues: 0, issues: [] };
  }

  const lines = code.split('\n');
  const hasGlobalReentrancyGuard = code.includes('nonReentrant');

  lines.forEach((lineText, idx) => {
    const lineNum = idx + 1;
    const trimmed = lineText.trim();
    const lowerLine = trimmed.toLowerCase();

    // Abaikan baris komentar
    if (trimmed.startsWith('//') || trimmed.startsWith('*')) return;

    // Rule 1: Reentrancy (Hanya deteksi jika fungsi TIDAK memakai nonReentrant)
    if (
      (trimmed.includes('.call{value:') || trimmed.includes('.call.value(') || trimmed.includes('.transfer(') || trimmed.includes('.send(')) &&
      !hasGlobalReentrancyGuard
    ) {
      issues.push({
        id: 'AEGIS-ARB-001',
        title: 'Potential Reentrancy Without Guard',
        severity: 'CRITICAL',
        cve: 'SWC-107',
        chain: 'arbitrum',
        line: lineNum,
        description: `External value call '${trimmed}' invoked without OpenZeppelin ReentrancyGuard modifier or CEI validation.`,
        recommendation: "Apply 'nonReentrant' modifier and adhere strictly to Checks-Effects-Interactions pattern.",
        diff: [
          { type: 'del', text: `- Line ${lineNum}: ${trimmed}` },
          { type: 'add', text: `+ Tambahkan modifier 'nonReentrant' pada fungsi penarikan ini` }
        ]
      });
    }

    // Rule 2: Arbitrum Sequencer Timestamp / Block Dependency
    if (trimmed.includes('block.timestamp') || trimmed.includes('block.number')) {
      issues.push({
        id: 'AEGIS-ARB-002',
        title: 'L2 Sequencer Timestamp / Block Discrepancy',
        severity: 'MEDIUM',
        cve: 'CWE-330',
        chain: 'arbitrum',
        line: lineNum,
        description: 'Arbitrum Nitro sequencing allows miners/sequencer small variations on block.timestamp, and block.number mirrors L1.',
        recommendation: 'Use ArbSys(address(100)).arbBlockNumber() for L2 block height or avoid strict timing logic.',
        diff: [
          { type: 'del', text: `- Line ${lineNum}: ${trimmed}` },
          { type: 'add', text: `+ Line ${lineNum}: ArbSys(address(100)).arbBlockNumber()` }
        ]
      });
    }

    // Rule 3: Missing Access Control on Critical Functions
    const isSensitive = lowerLine.includes('function withdraw') || 
                        lowerLine.includes('function mint') || 
                        lowerLine.includes('function setfee') || 
                        lowerLine.includes('function emergency');

    const isPublic = trimmed.includes('public') || trimmed.includes('external');
    const hasAuth = lowerLine.includes('onlyowner') || lowerLine.includes('onlyrole') || lowerLine.includes('auth');

    if (isSensitive && isPublic && !hasAuth) {
      issues.push({
        id: 'AEGIS-ARB-003',
        title: 'Missing Access Control on Critical Function',
        severity: 'CRITICAL',
        cve: 'CWE-284',
        chain: 'arbitrum',
        line: lineNum,
        description: `Critical administration function '${trimmed}' is exposed publicly without 'onlyOwner' or role-based modifier.`,
        recommendation: "Add an explicit access modifier such as 'onlyOwner' or OpenZeppelin AccessControl 'onlyRole(ADMIN_ROLE)'.",
        diff: [
          { type: 'del', text: `- Line ${lineNum}: ${trimmed}` },
          { type: 'add', text: `+ Line ${lineNum}: ${trimmed.replace('{', 'onlyOwner {')}` }
        ]
      });
    }
  });

  return {
    success: true,
    totalIssues: issues.length,
    issues: issues
  };
}

module.exports = { analyzeSolidityCode };
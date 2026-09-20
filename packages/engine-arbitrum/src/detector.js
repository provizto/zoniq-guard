// packages/engine-arbitrum/src/detector.js

function analyzeSolidityCode(code) {
  const issues = [];
  if (!code || typeof code !== 'string') {
    return { success: false, totalIssues: 0, issues: [] };
  }

  const lines = code.split('\n');

  lines.forEach((lineText, idx) => {
    const lineNum = idx + 1;

    // Rule 1: Reentrancy (State change after external call)
    if (
      (lineText.includes('.call{value:') || lineText.includes('.transfer(') || lineText.includes('.send(')) &&
      !lineText.includes('nonReentrant')
    ) {
      issues.push({
        id: 'ARB-001',
        title: 'Potential Reentrancy Without Guard',
        severity: 'CRITICAL',
        cve: 'CWE-841',
        chain: 'arbitrum',
        line: lineNum,
        description: `External value call '${lineText.trim()}' invoked without OpenZeppelin ReentrancyGuard modifier or CEI validation.`,
        recommendation: "Apply 'nonReentrant' modifier and adhere strictly to Checks-Effects-Interactions pattern."
      });
    }

    // Rule 2: Arbitrum Sequencer Timestamp Dependency
    if (lineText.includes('block.timestamp') || lineText.includes('block.number')) {
      issues.push({
        id: 'ARB-002',
        title: 'L2 Sequencer Timestamp Discrepancy',
        severity: 'MEDIUM',
        cve: 'CWE-330',
        chain: 'arbitrum',
        line: lineNum,
        description: 'Arbitrum Nitro sequencing allows miners/sequencer small variations on block.timestamp.',
        recommendation: "Do not use block.timestamp as a sole source of randomness or strict second-level timing."
      });
    }

    // Rule 3: Missing Access Control on Critical Functions
    const lowerLine = lineText.toLowerCase();
    if (
      (lowerLine.includes('function withdraw') || lowerLine.includes('function mint') || lowerLine.includes('function setfee')) &&
      (lineText.includes('public') || lineText.includes('external')) &&
      !lineText.includes('onlyowner') &&
      !lineText.includes('onlyrole') &&
      !lineText.includes('internal')
    ) {
      issues.push({
        id: 'ARB-003',
        title: 'Missing Access Control on Critical Function',
        severity: 'CRITICAL',
        cve: 'CWE-284',
        chain: 'arbitrum',
        line: lineNum,
        description: `Critical administration function '${lineText.trim()}' is exposed publicly without 'onlyOwner' or role-based modifier.`,
        recommendation: "Add an explicit access modifier such as 'onlyOwner' or OpenZeppelin AccessControl 'onlyRole(ADMIN_ROLE)'."
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
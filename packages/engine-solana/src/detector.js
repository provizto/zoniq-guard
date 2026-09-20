// packages/engine-solana/src/detector.js

function analyzeAnchorCode(code) {
  const issues = [];
  if (!code || typeof code !== 'string') {
    return { success: false, totalIssues: 0, issues: [] };
  }

  const lines = code.split('\n');

  lines.forEach((lineText, idx) => {
    const lineNum = idx + 1;

    // Rule 1: Missing Signer Constraint
    if (
      (lineText.includes('AccountInfo<') || lineText.includes('UncheckedAccount<')) &&
      (lineText.toLowerCase().includes('authority') || lineText.toLowerCase().includes('admin') || lineText.toLowerCase().includes('owner')) &&
      !lineText.includes('Signer<') &&
      !lineText.includes('#[account(signer)]')
    ) {
      issues.push({
        id: 'SOL-001',
        title: 'Missing Signer Constraint on Authority Account',
        severity: 'CRITICAL',
        cve: 'CWE-285',
        chain: 'solana',
        line: lineNum,
        description: `Account field '${lineText.trim()}' uses generic AccountInfo/UncheckedAccount without an enforced signature check.`,
        recommendation: "Replace 'AccountInfo' with 'Signer<'info>' or add an explicit '#[account(signer)]' attribute constraint."
      });
    }

    // Rule 2: Unchecked Account Usage
    if (lineText.includes('UncheckedAccount<') && !lineText.includes('/// CHECK:')) {
      issues.push({
        id: 'SOL-002',
        title: 'Undocumented UncheckedAccount',
        severity: 'HIGH',
        cve: 'CWE-20',
        chain: 'solana',
        line: lineNum,
        description: 'UncheckedAccount requires an explicit documentation comment explaining why safety checks are omitted.',
        recommendation: "Prepend the account field with an explicit '/// CHECK: <reason>' documentation comment."
      });
    }

    // Rule 3: Missing Canonical Bump Validation on PDA
    if (
      lineText.includes('seeds = [') &&
      !lineText.includes('bump')
    ) {
      issues.push({
        id: 'SOL-003',
        title: 'Missing Canonical Bump Validation on PDA',
        severity: 'HIGH',
        cve: 'CWE-345',
        chain: 'solana',
        line: lineNum,
        description: 'PDA seed definition does not constrain or validate the canonical bump seed, which may permit bump-sharing exploits.',
        recommendation: "Add a 'bump' constraint in the account attribute macro, e.g.: seeds = [...], bump = vault_account.bump"
      });
    }
  });

  return {
    success: true,
    totalIssues: issues.length,
    issues: issues
  };
}

module.exports = { analyzeAnchorCode };
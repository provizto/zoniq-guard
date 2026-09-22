// packages/engine-solana/src/detector.js

function analyzeAnchorCode(code) {
  const issues = [];
  if (!code || typeof code !== 'string') {
    return { success: false, totalIssues: 0, issues: [] };
  }

  const lines = code.split('\n');

  lines.forEach((lineText, idx) => {
    const lineNum = idx + 1;
    const trimmed = lineText.trim();
    const lowerLine = trimmed.toLowerCase();

    // Abaikan komentar
    if (trimmed.startsWith('//') || trimmed.startsWith('///') || trimmed.startsWith('*')) return;

    // Rule 1: Missing Signer Constraint on Authority Account
    const isAuthority = lowerLine.includes('authority') || lowerLine.includes('admin') || lowerLine.includes('owner');
    const isUnsafeAccount = trimmed.includes('AccountInfo<') || trimmed.includes('UncheckedAccount<');

    if (
      isUnsafeAccount &&
      isAuthority &&
      !trimmed.includes('Signer<') &&
      !trimmed.includes('#[account(signer)]')
    ) {
      issues.push({
        id: 'GUARD-SOL-001',
        title: 'Missing Signer Constraint on Authority Account',
        severity: 'CRITICAL',
        cve: 'CWE-285',
        chain: 'solana',
        line: lineNum,
        description: `Account field '${trimmed}' uses generic AccountInfo/UncheckedAccount without an enforced signature check.`,
        recommendation: "Replace 'AccountInfo' with 'Signer<'info>' or add an explicit '#[account(signer)]' attribute constraint.",
        diff: [
          { type: 'del', text: `- Line ${lineNum}: ${trimmed}` },
          { 
            type: 'add', 
            text: `+ Line ${lineNum}: ${trimmed.replace(/AccountInfo<'info>|UncheckedAccount<'info>/g, "Signer<'info>")}` 
          }
        ],
        remediationCode: trimmed.replace(/AccountInfo<'info>|UncheckedAccount<'info>/g, "Signer<'info>")
      });
    }

    // Rule 2: Undocumented UncheckedAccount (Cek baris saat ini dan baris sebelumnya untuk /// CHECK:)
    if (trimmed.includes('UncheckedAccount<')) {
      const prevLine = idx > 0 ? lines[idx - 1].trim() : '';
      const hasDocCheck = prevLine.startsWith('/// CHECK:') || trimmed.includes('/// CHECK:');

      if (!hasDocCheck) {
        issues.push({
          id: 'GUARD-SOL-002',
          title: 'Undocumented UncheckedAccount',
          severity: 'HIGH',
          cve: 'CWE-20',
          chain: 'solana',
          line: lineNum,
          description: 'UncheckedAccount requires an explicit documentation comment explaining why safety checks are omitted.',
          recommendation: "Prepend the account field with an explicit '/// CHECK: <reason>' documentation comment.",
          diff: [
            { type: 'del', text: `- Line ${lineNum}: ${trimmed}` },
            { type: 'add', text: `+ Line ${lineNum}: /// CHECK: Validated via custom logic\n    ${trimmed}` }
          ],
          remediationCode: `/// CHECK: Validated via custom logic\n    ${trimmed}`
        });
      }
    }

    // Rule 3: Missing Canonical Bump Validation on PDA
    if (
      (trimmed.includes('seeds = [') || trimmed.includes('seeds=[')) &&
      !trimmed.includes('bump')
    ) {
      // Cek apakah deklarasi bump ada di 2 baris setelahnya (jika multiline)
      const multiLineCheck = lines.slice(idx, idx + 3).join(' ');
      if (!multiLineCheck.includes('bump')) {
        issues.push({
          id: 'GUARD-SOL-003',
          title: 'Missing Canonical Bump Validation on PDA',
          severity: 'HIGH',
          cve: 'CWE-345',
          chain: 'solana',
          line: lineNum,
          description: 'PDA seed definition does not constrain or validate the canonical bump seed, which may permit bump-sharing exploits.',
          recommendation: "Add a 'bump' constraint in the account attribute macro, e.g.: seeds = [...], bump",
          diff: [
            { type: 'del', text: `- Line ${lineNum}: ${trimmed}` },
            { type: 'add', text: `+ Line ${lineNum}: ${trimmed.replace(/\]\s*\)/, '], bump)')}` }
          ],
          remediationCode: trimmed.replace(/\]\s*\)/, '], bump)')
        });
      }
    }
  });

  return {
    success: true,
    totalIssues: issues.length,
    issues: issues
  };
}

module.exports = { analyzeAnchorCode };
const express = require('express');
const cors = require('cors');

const { analyzeSolidityCode } = require('../../packages/engine-arbitrum/src/detector');
const { analyzeAnchorCode } = require('../../packages/engine-solana/src/detector');

const app = express();
const PORT = process.env.PORT || 4000;

app.use(cors());
app.use(express.json());

app.get('/api/health', (req, res) => {
  res.json({
    status: 'online',
    service: 'Zoniqfi Aegis Security Core API',
    supportedChains: ['solana', 'arbitrum', 'base', 'polygon', 'ethereum'],
    timestamp: new Date().toISOString()
  });
});

app.post('/api/audit', (req, res) => {
  // 1. Ambil userTier dari payload request (default: 'free' jika tidak dikirim)
  const { code, chain, filename, activeRules, userTier = 'free' } = req.body;

  if (!code || typeof code !== 'string') {
    return res.status(400).json({
      success: false,
      error: 'Missing or invalid "code" payload.'
    });
  }

  let selectedChain = (chain || 'auto').toLowerCase();
  
  // Intelligent Auto-Detection: detect if source is Solana (Rust/Anchor) or EVM (Solidity)
  const isRustAnchor = code.includes('anchor_lang') || code.includes('#[program]') || (filename && filename.endsWith('.rs'));
  const isSolidity = code.includes('pragma solidity') || code.includes('contract ') || (filename && filename.endsWith('.sol'));

  if (selectedChain === 'all' || selectedChain === 'auto') {
    selectedChain = isRustAnchor ? 'solana' : 'arbitrum';
  }

  let auditResult;

  try {
    if (selectedChain === 'solana' || isRustAnchor) {
      auditResult = analyzeAnchorCode(code);
      selectedChain = 'solana';
    } else {
      auditResult = analyzeSolidityCode(code);
    }

    if (!auditResult.success && auditResult.error) {
      return res.json({
        success: false,
        error: auditResult.error,
        totalIssues: 0,
        issues: []
      });
    }

    let filteredIssues = auditResult.issues || [];

    // 2. LOGIKA TIER: Gating fitur Reentrancy khusus Enterprise
    // Jika bukan Enterprise, matikan aturan Reentrancy (AEGIS-ARB-001)
    const isEnterprise = userTier.toLowerCase() === 'enterprise';
    if (!isEnterprise) {
      filteredIssues = filteredIssues.filter(issue => issue.id !== 'AEGIS-ARB-001');
    }

    // 3. Filter issues berdasarkan activeRules toggle dari UI dashboard
    if (activeRules) {
      filteredIssues = filteredIssues.filter(issue => {
        if (issue.id === 'AEGIS-SOL-001') return activeRules.sol001 ?? true;
        if (issue.id === 'AEGIS-SOL-002') return activeRules.sol002 ?? true;
        if (issue.id === 'AEGIS-ARB-001') return isEnterprise && (activeRules.arb001 ?? true);
        if (issue.id === 'AEGIS-ARB-002') return activeRules.arb002 ?? true;
        return true;
      });
    }

    return res.json({
      success: true,
      targetFile: filename || (selectedChain === 'solana' ? 'lib.rs' : 'Contract.sol'),
      chain: selectedChain,
      tierApplied: userTier,
      totalIssues: filteredIssues.length,
      issues: filteredIssues,
      scannedAt: new Date().toISOString()
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      error: `Internal audit execution failure: ${err.message}`
    });
  }
});

app.listen(PORT, () => {
  console.log(`[AEGIS-CORE] Security Orchestration API running at http://localhost:${PORT}`);
  console.log(`[AEGIS-CORE] Ready to receive audit payloads from apps/web dashboard.`);
});
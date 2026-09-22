require('dotenv').config();
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
    service: 'Zoniq Guard Security Core API',
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

// ENDPOINT TELEGRAM AMAN (TOKEN TERSEMBUNYI DI .ENV)
app.post('/api/notify-payment', async (req, res) => {
  const { planType, txHash, network, buyerWallet } = req.body;
  
  const botToken = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.TELEGRAM_CHAT_ID;

  if (!botToken || !chatId) {
    console.error("[ZONIQ-GUARD] TELEGRAM_BOT_TOKEN atau TELEGRAM_CHAT_ID belum ada di .env");
    return res.status(500).json({ success: false, error: 'Telegram credentials missing on server.' });
  }

  const message = 
    `💰 *PEMBAYARAN PAKET MASUK!*\n\n` +
    `📦 *Paket:* ${(planType || 'PRO').toUpperCase()}\n` +
    `🌐 *Jaringan:* ${network || 'Unknown'}\n` +
    `👤 *Pembeli:* \`${buyerWallet || 'Anonymous'}\`\n` +
    `🔗 *Tx Hash:* \`${txHash}\`\n\n` +
    `_Zoniq Guard Production Notifier._`;

  try {
    const tgRes = await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: chatId,
        text: message,
        parse_mode: 'Markdown'
      })
    });
    const result = await tgRes.json();
    return res.json({ success: result.ok });
  } catch (err) {
    console.error("[ZONIQ-GUARD] Gagal kirim notif Telegram:", err);
    return res.status(500).json({ success: false, error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`[ZONIQ-GUARD] Security Core API running at http://localhost:${PORT}`);
  console.log(`[ZONIQ-GUARD] Ready to receive audit & payment payloads.`);
});
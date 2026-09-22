import express from 'express';
import cors from 'cors';

const app = express();
const PORT = 4000;

app.use(cors());
app.use(express.json());

// Aturan audit Solana & Arbitrum
const RULES = {
  solana: [
    {
      id: "SOL-001",
      title: "Missing Signer Check on Vault Authority",
      severity: "critical",
      chain: "solana",
      cve: "CWE-285",
      impact: "Complete drainage of protocol funds. An attacker can craft a transaction providing the admin key without signing.",
      fixSummary: "Convert 'pub authority: AccountInfo' to 'pub authority: Signer' in the Anchor Accounts macro struct.",
      diff: [
        { type: "context", text: " #[derive(Accounts)]" },
        { type: "context", text: " pub struct WithdrawTreasury<'info> {" },
        { type: "del",     text: "-    pub authority: AccountInfo<'info>," },
        { type: "add",     text: "+    pub authority: Signer<'info>," },
        { type: "context", text: " }" }
      ],
      remediationCode: "pub authority: Signer<'info>,",
      check: (code) => code.includes("AccountInfo<'info>") && (code.includes("authority") || code.includes("admin") || code.includes("owner"))
    }
  ],
  arbitrum: [
    {
      id: "ARB-001",
      title: "Reentrancy in withdrawBalance()",
      severity: "high",
      chain: "arbitrum",
      cve: "SWC-107",
      impact: "External call is executed before state variable is cleared, enabling re-entrancy drain.",
      fixSummary: "Zero the balance prior to invoking call{value: ...}, or apply OpenZeppelin nonReentrant.",
      diff: [
        { type: "context", text: "     function withdraw() external {" },
        { type: "add",     text: "+        balances[msg.sender] = 0; // Checks-Effects-Interactions" },
        { type: "del",     text: "-        (bool sent, ) = msg.sender.call{value: bal}(\"\");" },
        { type: "context", text: "     }" }
      ],
      remediationCode: "balances[msg.sender] = 0;\n(bool sent, ) = msg.sender.call{value: bal}(\"\");",
      check: (code) => code.includes(".call{value:") && code.includes("balances[msg.sender] = 0")
    }
  ]
};

app.post('/api/scan', (req, res) => {
  const { code, chain = 'solana' } = req.body;

  if (!code) {
    return res.status(400).json({ error: "Source code cannot be empty." });
  }

  const activeRules = RULES[chain.toLowerCase()] || [];
  const findings = [];

  activeRules.forEach(rule => {
    if (rule.check(code)) {
      findings.push({
        id: rule.id,
        title: rule.title,
        severity: rule.severity,
        chain: rule.chain,
        cve: rule.cve,
        file: chain === 'solana' ? 'programs/vault/src/lib.rs' : 'contracts/CommerceGateway.sol',
        summary: rule.impact,
        impact: rule.impact,
        fixSummary: rule.fixSummary,
        diff: rule.diff,
        remediationCode: rule.remediationCode
      });
    }
  });

  return res.json({
    success: true,
    totalIssues: findings.length,
    findings: findings,
    auditedAt: new Date().toISOString()
  });
});

app.listen(PORT, () => {
  console.log(`🚀 Guard Core Engine API live on http://localhost:${PORT}`);
});
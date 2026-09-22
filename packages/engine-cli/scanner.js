#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';

/**
 * Zoniq Guard Security Core - Static Analysis CLI Scanner
 * Evaluates Solana (Rust/Anchor) and Arbitrum/EVM (Solidity) AST & Syntax Rules.
 */

const RULES = {
  solana: [
    {
      id: "SOL-001",
      name: "Missing Signer Check",
      severity: "CRITICAL",
      cwe: "CWE-285",
      test: (content) => {
        const matches = [];
        const lines = content.split('\n');
        lines.forEach((line, index) => {
          if (line.includes("AccountInfo<'info>") && (line.includes("authority") || line.includes("owner") || line.includes("admin"))) {
            matches.push({
              line: index + 1,
              code: line.trim(),
              advice: "Replace 'AccountInfo' with 'Signer<'info>' to enforce cryptographic signature verification."
            });
          }
        });
        return matches;
      }
    },
    {
      id: "SOL-002",
      name: "Unchecked Account Mutability",
      severity: "HIGH",
      cwe: "CWE-665",
      test: (content) => {
        const matches = [];
        const lines = content.split('\n');
        lines.forEach((line, index) => {
          if (line.includes("#[account(mut)]") && lines[index + 1] && lines[index + 1].includes("AccountInfo<'info>")) {
            matches.push({
              line: index + 1,
              code: line.trim(),
              advice: "Mutable AccountInfo must enforce ownership constraint or custom validation."
            });
          }
        });
        return matches;
      }
    }
  ],
  arbitrum: [
    {
      id: "ARB-001",
      name: "Reentrancy Vulnerability (Checks-Effects-Interactions)",
      severity: "HIGH",
      cwe: "CWE-841",
      test: (content) => {
        const matches = [];
        const lines = content.split('\n');
        let callFoundLine = -1;

        lines.forEach((line, index) => {
          if (line.includes(".call{value:") || line.includes(".transfer(") || line.includes(".send(")) {
            callFoundLine = index + 1;
          }
          if (callFoundLine > 0 && index + 1 > callFoundLine && index + 1 <= callFoundLine + 5) {
            if (line.includes("balances[") && line.includes("=") && !line.includes("==")) {
              matches.push({
                line: callFoundLine,
                code: line.trim(),
                advice: "State updated after external transfer call. Move state change before external call or use ReentrancyGuard."
              });
            }
          }
        });
        return matches;
      }
    }
  ]
};

function runAudit(targetFilePath, ecosystem = 'solana') {
  console.log(`\n======================================================`);
  console.log(`🛡️  ZONIQ GUARD STATIC AUDIT ENGINE`);
  console.log(`Target: ${targetFilePath} | Ecosystem: ${ecosystem.toUpperCase()}`);
  console.log(`======================================================\n`);

  if (!fs.existsSync(targetFilePath)) {
    console.error(`❌ Error: File not found: ${targetFilePath}`);
    process.exit(1);
  }

  const content = fs.readFileSync(targetFilePath, 'utf8');
  const targetRules = RULES[ecosystem.toLowerCase()] || [];
  let totalIssues = 0;

  targetRules.forEach((rule) => {
    const findings = rule.test(content);
    if (findings.length > 0) {
      findings.forEach((finding) => {
        totalIssues++;
        console.log(`[${rule.severity}] ${rule.id} - ${rule.name} (${rule.cwe})`);
        console.log(`  Location: Line ${finding.line}`);
        console.log(`  Code:     ${finding.code}`);
        console.log(`  Fix:      ${finding.advice}\n`);
      });
    }
  });

  if (totalIssues === 0) {
    console.log(`✅ Clean pass! Zero rule violations detected.`);
    process.exit(0);
  } else {
    console.log(`⚠️ Audit completed with ${totalIssues} security violation(s).\n`);
    process.exit(1);
  }
}

// Parse CLI flags
const args = process.argv.slice(2);
const fileArg = args[0] || "tests/sample_vault.rs";
const chainArg = args.includes("--chain") ? args[args.indexOf("--chain") + 1] : "solana";

runAudit(fileArg, chainArg);
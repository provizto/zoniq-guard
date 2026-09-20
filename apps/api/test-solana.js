// apps/api/test-solana.js

async function testAudit() {
  const payload = {
    chain: "solana",
    filename: "lib.rs",
    code: `#[program]
pub mod vault {
  pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> {}
}
#[derive(Accounts)]
pub struct Withdraw<'info> {
  pub authority: AccountInfo<'info>,
}`
  };

  try {
    const response = await fetch("http://localhost:4000/api/audit", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    const data = await response.json();
    console.log("\n=== HASIL AUDIT DARI API ===");
    console.log(JSON.stringify(data, null, 2));
  } catch (error) {
    console.error("Gagal terhubung ke server:", error.message);
  }
}

testAudit();
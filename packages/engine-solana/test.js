const { analyzeAnchorCode } = require('./src/detector');

// Vulnerable Anchor Program Fixture
const testAnchorCode = `use anchor_lang::prelude::*;

declare_id!("Zon1qCoreSecureProtocol1111111111111111111");

#[program]
pub mod zoniq_vault {
    use super::*;

    pub fn withdraw(ctx: Context<WithdrawTreasury>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        require!(ctx.accounts.authority.key() == vault.admin, VaultError::Unauthorized);
        **ctx.accounts.vault.to_account_info().try_borrow_mut_lamports()? -= amount;
        **ctx.accounts.recipient.to_account_info().try_borrow_mut_lamports()? += amount;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct WithdrawTreasury<'info> {
    #[account(mut, seeds = [b"vault", vault.admin.as_ref()])]
    pub vault: Account<'info, VaultData>,

    /// CHECK: Insecure raw AccountInfo without Signer validation
    pub authority: AccountInfo<'info>,

    #[account(mut)]
    pub recipient: AccountInfo<'info>,
}

#[account]
pub struct VaultData {
    pub admin: Pubkey,
}

#[error_code]
pub enum VaultError {
    #[msg("Unauthorized")]
    Unauthorized,
}
`;

console.log("Executing Solana Anchor AST Security Analysis...");
const report = analyzeAnchorCode(testAnchorCode);
console.log(JSON.stringify(report, null, 2));
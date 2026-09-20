use anchor_lang::prelude::*;

declare_id!("Zon1qFi1111111111111111111111111111111111111");

#[program]
pub mod zoniq_vault {
    use super::*;

    pub fn withdraw_admin(ctx: Context<WithdrawAdmin>, amount: u64) -> Result<()> {
        // Business logic execution
        msg!("Withdraw admin executed for amount: {}", amount);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct WithdrawAdmin<'info> {
    #[account(mut)]
    pub vault: Account<'info, VaultData>,

    // VULNERABLE: Missing Signer constraint (AccountInfo allows anyone to spoof this address)
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[account]
pub struct VaultData {
    pub balance: u64,
}
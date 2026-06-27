use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
};

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    msg!("Hello Solana!");
    
    let account_info_iter = &mut accounts.iter();
    let account = next_account_info(account_info_iter)?;
    
    // Example: check signer (good practice)
    if !account.is_signer {
        msg!("Missing signer");
        return Err(ProgramError::MissingRequiredSignature);
    }
    
    msg!("Processing complete");
    Ok(())
}
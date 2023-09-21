use near_sdk::AccountId;

pub fn acc_voting_body() -> AccountId {
    AccountId::new_unchecked("votingbody.near".to_string())
}

pub fn council_of_advisors() -> AccountId {
    AccountId::new_unchecked("coa.near".to_string())
}

pub fn ndc_trust() -> AccountId {
    AccountId::new_unchecked("ndctrust.near".to_string())
}

/// creates council member account
pub fn council(i: u32) -> AccountId {
    AccountId::new_unchecked(format!("council-{}.near", i))
}

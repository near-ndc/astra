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

pub fn council_member_1() -> AccountId {
    AccountId::new_unchecked("council1.near".to_string())
}

pub fn council_member_2() -> AccountId {
    AccountId::new_unchecked("council2.near".to_string())
}

pub fn council_member_3() -> AccountId {
    AccountId::new_unchecked("council3.near".to_string())
}

pub fn council_member_4() -> AccountId {
    AccountId::new_unchecked("council1.near".to_string())
}

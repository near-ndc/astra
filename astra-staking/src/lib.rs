use near_contract_standards::fungible_token::core::ext_ft_core;
use near_contract_standards::fungible_token::receiver::FungibleTokenReceiver;
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::LookupMap;
use near_sdk::json_types::{U128, U64};
use near_sdk::{
    env, ext_contract, near_bindgen, AccountId, Balance, BorshStorageKey, Duration, Gas,
    PanicOnDefault, Promise, PromiseOrValue, PromiseResult,
};

pub use user::{User, VersionedUser};

mod storage_impl;
mod user;

#[derive(BorshStorageKey, BorshSerialize)]
enum StorageKeys {
    Users,
}

/// Amount of gas for fungible token transfers.
pub const GAS_FOR_FT_TRANSFER: Gas = Gas(10_000_000_000_000);

/// Amount of gas for delegate action.
pub const GAS_FOR_DELEGATE: Gas = Gas(10_000_000_000_000);

/// Amount of gas for register action.
pub const GAS_FOR_REGISTER: Gas = Gas(10_000_000_000_000);

/// Amount of gas for undelegate action.
pub const GAS_FOR_UNDELEGATE: Gas = Gas(10_000_000_000_000);

#[ext_contract(ext_astra)]
pub trait ExtAstra {
    fn register_delegation(&mut self, account_id: AccountId);
    fn delegate(&mut self, account_id: AccountId, amount: U128);
    fn undelegate(&mut self, account_id: AccountId, amount: U128);
}

#[near_bindgen]
#[derive(BorshSerialize, BorshDeserialize, PanicOnDefault)]
pub struct Contract {
    /// DAO owner of this staking contract.
    owner_id: AccountId,
    /// Vote token account.
    vote_token_id: AccountId,
    /// Recording user deposits.
    users: LookupMap<AccountId, VersionedUser>,
    /// Total token amount deposited.
    total_amount: Balance,
    /// Duration of unstaking. Should be over the possible voting periods.
    unstake_period: Duration,
}

#[ext_contract(ext_self)]
pub trait ExtSelf {
    fn exchange_callback_post_withdraw(&mut self, sender_id: AccountId, amount: U128);
}

#[near_bindgen]
impl Contract {
    #[init]
    pub fn new(owner_id: AccountId, token_id: AccountId, unstake_period: U64) -> Self {
        Self {
            owner_id,
            vote_token_id: token_id,
            users: LookupMap::new(StorageKeys::Users),
            total_amount: 0,
            unstake_period: unstake_period.0,
        }
    }

    /// Total number of tokens staked in this contract.
    pub fn ft_total_supply(&self) -> U128 {
        U128(self.total_amount)
    }

    /// Total number of tokens staked by given user.
    pub fn ft_balance_of(&self, account_id: AccountId) -> U128 {
        U128(self.internal_get_user(&account_id).vote_amount.0)
    }

    /// Returns user information.
    pub fn get_user(&self, account_id: AccountId) -> User {
        self.internal_get_user(&account_id)
    }

    /// Delegate give amount of votes to given account.
    /// If enough tokens and storage, forwards this to owner account.
    pub fn delegate(&mut self, account_id: AccountId, amount: U128) -> Promise {
        let sender_id = env::predecessor_account_id();
        self.internal_delegate(sender_id, account_id.clone(), amount.0);
        ext_astra::ext(self.owner_id.clone())
        .with_static_gas(GAS_FOR_DELEGATE)
        .delegate(
            account_id,
            amount
        )
    }

    /// Remove given amount of delegation.
    pub fn undelegate(&mut self, account_id: AccountId, amount: U128) -> Promise {
        let sender_id = env::predecessor_account_id();
        self.internal_undelegate(sender_id, account_id.clone(), amount.0);
        ext_astra::ext(self.owner_id.clone())
        .with_static_gas(GAS_FOR_UNDELEGATE)
        .undelegate(
            account_id,
            amount
        )
    }

    /// Withdraw non delegated tokens back to the user's account.
    /// If user's account is not registered, will keep funds here.
    pub fn withdraw(&mut self, amount: U128) -> Promise {
        let sender_id = env::predecessor_account_id();
        self.internal_withdraw(&sender_id, amount.0);
        ext_ft_core::ext(self.vote_token_id.clone())
            .with_static_gas(GAS_FOR_FT_TRANSFER)
            .with_attached_deposit(1)
            .ft_transfer(
                sender_id.clone(),
                amount,
                None
        )
        .then(ext_self::ext(env::current_account_id())
            .with_static_gas(GAS_FOR_FT_TRANSFER)
            .exchange_callback_post_withdraw(
                sender_id,
                amount
            )
        )
    }

    #[private]
    pub fn exchange_callback_post_withdraw(&mut self, sender_id: AccountId, amount: U128) {
        assert_eq!(
            env::promise_results_count(),
            1,
            "ERR_CALLBACK_POST_WITHDRAW_INVALID",
        );
        match env::promise_result(0) {
            PromiseResult::NotReady => unreachable!(),
            PromiseResult::Successful(_) => {}
            PromiseResult::Failed => {
                // This reverts the changes from withdraw function.
                self.internal_deposit(&sender_id, amount.0);
            }
        };
    }
}

#[near_bindgen]
impl FungibleTokenReceiver for Contract {
    fn ft_on_transfer(
        &mut self,
        sender_id: AccountId,
        amount: U128,
        msg: String,
    ) -> PromiseOrValue<U128> {
        assert_eq!(
            self.vote_token_id,
            env::predecessor_account_id(),
            "ERR_INVALID_TOKEN"
        );
        assert!(msg.is_empty(), "ERR_INVALID_MESSAGE");
        self.internal_deposit(&sender_id, amount.0);
        PromiseOrValue::Value(U128(0))
    }
}

#[cfg(test)]
mod tests {
    use near_contract_standards::storage_management::StorageManagement;
    use near_sdk::json_types::U64;
    use near_sdk::test_utils::{accounts, VMContextBuilder};
    use near_sdk::testing_env;

    use near_units::parse_near;

    use super::*;

    #[test]
    fn test_basics() {
        const UNSTAKE_PERIOD: u64 = 1000;
        let contract_owner: AccountId = accounts(0);
        let voting_token: AccountId = accounts(1);
        let delegate_from_user: AccountId = accounts(2);
        let delegate_to_user: AccountId = accounts(3);

        let mut context = VMContextBuilder::new();

        testing_env!(context
            .predecessor_account_id(contract_owner.clone())
            .build());
        let mut contract = Contract::new(contract_owner, voting_token.clone(), U64(UNSTAKE_PERIOD));

        testing_env!(context.attached_deposit(parse_near!("1 N")).build());
        contract.storage_deposit(Some(delegate_from_user.clone()), None);

        testing_env!(context.predecessor_account_id(voting_token).build());
        contract.ft_on_transfer(
            delegate_from_user.clone(),
            U128(parse_near!("100")),
            "".to_string(),
        );
        assert_eq!(contract.ft_total_supply().0, parse_near!("100 N"));
        assert_eq!(
            contract.ft_balance_of(delegate_from_user.clone()).0,
            parse_near!("100")
        );

        testing_env!(context
            .predecessor_account_id(delegate_from_user.clone())
            .build());
        contract.withdraw(U128(parse_near!("50 N")));
        assert_eq!(contract.ft_total_supply().0, parse_near!("50 N"));
        assert_eq!(
            contract.ft_balance_of(delegate_from_user.clone()).0,
            parse_near!("50")
        );

        testing_env!(context.attached_deposit(parse_near!("1 N")).build());
        contract.storage_deposit(Some(delegate_to_user.clone()), None);

        contract.delegate(delegate_to_user.clone(), U128(parse_near!("10 N")));
        let user = contract.get_user(delegate_from_user.clone());
        assert_eq!(user.delegated_amount(), parse_near!("10 N"));

        contract.undelegate(delegate_to_user, U128(parse_near!("10 N")));
        let user = contract.get_user(delegate_from_user);
        assert_eq!(user.delegated_amount(), 0);
        assert_eq!(user.next_action_timestamp, U64(UNSTAKE_PERIOD));
    }
}

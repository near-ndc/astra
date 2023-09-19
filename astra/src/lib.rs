use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::{LazyOption, LookupMap};
use near_sdk::json_types::{Base58CryptoHash, U128};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{
    env, ext_contract, near_bindgen, AccountId, Balance, BorshStorageKey, CryptoHash,
    PanicOnDefault, Promise, PromiseResult, PromiseOrValue,
};
use policy::UserInfo;

pub use crate::bounties::{Bounty, BountyClaim, VersionedBounty};
pub use crate::policy::{
    default_policy, Policy, RoleKind, RolePermission, VersionedPolicy, VotePolicy,
};
use crate::proposals::VersionedProposal;
pub use crate::proposals::{Proposal, ProposalInput, ProposalKind, ProposalStatus};
pub use crate::types::{Action, Config, OldAccountId, OLD_BASE_TOKEN};
use crate::upgrade::{internal_get_factory_info, internal_set_factory_info, FactoryInfo};
pub use crate::views::{BountyOutput, ProposalOutput};

mod bounties;
mod delegation;
mod policy;
mod proposals;
mod types;
mod upgrade;
pub mod views;

#[derive(BorshStorageKey, BorshSerialize)]
pub enum StorageKeys {
    Config,
    Policy,
    Delegations,
    Proposals,
    Bounties,
    BountyClaimers,
    BountyClaimCounts,
    Blobs,
}

/// After payouts, allows a callback
#[ext_contract(ext_self)]
pub trait ExtSelf {
    /// Callback after proposal execution.
    fn on_proposal_callback(&mut self, proposal_id: u64) -> PromiseOrValue<()>;
}

#[near_bindgen]
#[derive(BorshSerialize, BorshDeserialize, PanicOnDefault)]
pub struct Contract {
    /// DAO configuration.
    pub config: LazyOption<Config>,
    /// Voting and permissions policy.
    pub policy: LazyOption<VersionedPolicy>,

    /// Amount of $NEAR locked for bonds.
    pub locked_amount: Balance,

    /// Vote staking contract id. That contract must have this account as owner.
    pub staking_id: Option<AccountId>,
    /// Delegated  token total amount.
    pub total_delegation_amount: Balance,
    /// Delegations per user.
    pub delegations: LookupMap<AccountId, Balance>,

    /// Last available id for the proposals.
    pub last_proposal_id: u64,
    /// Proposal map from ID to proposal information.
    pub proposals: LookupMap<u64, VersionedProposal>,

    /// Last available id for the bounty.
    pub last_bounty_id: u64,
    /// Bounties map from ID to bounty information.
    pub bounties: LookupMap<u64, VersionedBounty>,
    /// Bounty claimers map per user. Allows quickly to query for each users their claims.
    pub bounty_claimers: LookupMap<AccountId, Vec<BountyClaim>>,
    /// Count of claims per bounty.
    pub bounty_claims_count: LookupMap<u64, u32>,

    /// Large blob storage.
    pub blobs: LookupMap<CryptoHash, AccountId>,

    /// Trust address
    pub trust: AccountId,
}

#[near_bindgen]
impl Contract {
    #[init]
    pub fn new(config: Config, policy: VersionedPolicy, trust: AccountId) -> Self {
        let this = Self {
            config: LazyOption::new(StorageKeys::Config, Some(&config)),
            policy: LazyOption::new(StorageKeys::Policy, Some(&policy.upgrade())),
            staking_id: None,
            total_delegation_amount: 0,
            delegations: LookupMap::new(StorageKeys::Delegations),
            last_proposal_id: 0,
            proposals: LookupMap::new(StorageKeys::Proposals),
            last_bounty_id: 0,
            bounties: LookupMap::new(StorageKeys::Bounties),
            bounty_claimers: LookupMap::new(StorageKeys::BountyClaimers),
            bounty_claims_count: LookupMap::new(StorageKeys::BountyClaimCounts),
            blobs: LookupMap::new(StorageKeys::Blobs),
            locked_amount: 0,
            trust,
        };
        internal_set_factory_info(&FactoryInfo {
            factory_id: env::predecessor_account_id(),
            auto_update: true,
        });
        this
    }

    /// Should only be called by this contract on migration.
    /// This is NOOP implementation. KEEP IT if you haven't changed contract state.
    /// If you have changed state, you need to implement migration from old state (keep the old struct with different name to deserialize it first).
    /// After migrate goes live on MainNet, return this implementation for next updates.
    #[private]
    #[init(ignore_state)]
    pub fn migrate() -> Self {
        let this: Contract = env::state_read().expect("ERR_CONTRACT_IS_NOT_INITIALIZED");
        this
    }

    /// Remove blob from contract storage and pay back to original storer.
    /// Only original storer can call this.
    pub fn remove_blob(&mut self, hash: Base58CryptoHash) -> Promise {
        let hash: CryptoHash = hash.into();
        let account_id = self.blobs.remove(&hash).expect("ERR_NO_BLOB");
        assert_eq!(
            env::predecessor_account_id(),
            account_id,
            "ERR_INVALID_CALLER"
        );
        env::storage_remove(&hash);
        let blob_len = env::register_len(u64::MAX - 1).unwrap();
        let storage_cost = ((blob_len + 32) as u128) * env::storage_byte_cost();
        Promise::new(account_id).transfer(storage_cost)
    }

    /// Returns factory information, including if auto update is allowed.
    pub fn get_factory_info(&self) -> FactoryInfo {
        internal_get_factory_info()
    }

    /// Veto proposal hook
    /// Check for authorities and remove proposal
    /// * `id`: proposal id
    /// TODO: Add events for veto and dissolve
    pub fn veto(&mut self, id: u64) {
        if let Some(pol) = self.policy.get() {
            let policy = pol.to_policy();
            let res = 
            policy.can_execute_action(UserInfo {
                amount: 0u128,
                account_id: env::predecessor_account_id(),
            }, &ProposalKind::VetoProposal{}, &Action::VetoProposal);
            assert!(res.1, "not authorized");
        } else {
            panic!("policy not found!")
        }

        // Check if the proposal exist and is not finalized
        if let Some(prop) = self.proposals.get(&id) {
            let proposal: Proposal = prop.into();
            match proposal.status {
                ProposalStatus::InProgress | ProposalStatus::Failed => {
                    // Remove the proposal if it's in progress or failed
                    self.proposals.remove(&id);
                }
                _ => {
                    // Panic if the proposal is finalized
                    panic!("Proposal finalized");
                }
            }
        } else {
            panic!("proposal does not exist");
        }
       
    }

    /// Dissolves the DAO by removing all members, closing all active proposals and returning bonds.
    /// Transfers all reminding funds to the trust.
    /// Panics if policy doesn't exist or accound is not authorised to execute dissolve
    pub fn dissolve(&mut self) {
        let mut policy;
        if let Some(pol) = self.policy.get() {
            policy = pol.to_policy();
            let res = 
            policy.can_execute_action(UserInfo {
                amount: 0u128,
                account_id: env::predecessor_account_id(),
            }, &ProposalKind::Dissolve{}, &Action::Dissolve);
            assert!(res.1, "not authorized");
        } else {
            panic!("policy not found!")
        }

        // Return bond amounts
        for prop_id in 0..self.last_proposal_id {
            let prop: Proposal = self.proposals.get(&prop_id).unwrap().into();
            if prop.status == ProposalStatus::InProgress {
                self.internal_return_bonds(&policy, &prop);
            }
            self.proposals.remove(&prop_id);
        }

        policy.roles = vec![];
        self.policy.set(&VersionedPolicy::Current(policy));

        let funds = env::account_balance() - self.locked_amount;
        Promise::new(self.trust.clone()).transfer(funds);
    }
}

/// Stores attached data into blob store and returns hash of it.
/// Implemented to avoid loading the data into WASM for optimal gas usage.
#[no_mangle]
pub extern "C" fn store_blob() {
    env::setup_panic_hook();
    let mut contract: Contract = env::state_read().expect("ERR_CONTRACT_IS_NOT_INITIALIZED");
    let input = env::input().expect("ERR_NO_INPUT");
    let sha256_hash = env::sha256(&input);
    assert!(!env::storage_has_key(&sha256_hash), "ERR_ALREADY_EXISTS");

    let blob_len = input.len();
    let storage_cost = ((blob_len + 32) as u128) * env::storage_byte_cost();
    assert!(
        env::attached_deposit() >= storage_cost,
        "ERR_NOT_ENOUGH_DEPOSIT:{}",
        storage_cost
    );

    env::storage_write(&sha256_hash, &input);
    let mut blob_hash = [0u8; 32];
    blob_hash.copy_from_slice(&sha256_hash);
    contract
        .blobs
        .insert(&blob_hash, &env::predecessor_account_id());
    let blob_hash_str = near_sdk::serde_json::to_string(&Base58CryptoHash::from(blob_hash))
        .unwrap()
        .into_bytes();

    env::value_return(&blob_hash_str);
    env::state_write(&contract);
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap};

    use near_sdk::json_types::U64;
    use near_sdk::test_utils::{accounts, VMContextBuilder};
    use near_sdk::{testing_env, VMContext};
    use near_units::parse_near;

    use crate::proposals::ProposalStatus;

    use super::*;

    fn acc_voting_body() -> AccountId {
        AccountId::new_unchecked("votingbody.near".to_string())
    }

    fn council_of_advisors() -> AccountId {
        AccountId::new_unchecked("coa.near".to_string())
    }

    fn ndc_trust() -> AccountId {
        AccountId::new_unchecked("ndctrust.near".to_string())
    }

    fn council_member_1() -> AccountId {
        AccountId::new_unchecked("council1.near".to_string())
    }

    fn council_member_2() -> AccountId {
        AccountId::new_unchecked("council2.near".to_string())
    }

    fn council_member_3() -> AccountId {
        AccountId::new_unchecked("council3.near".to_string())
    }

    fn create_proposal(context: &mut VMContextBuilder, contract: &mut Contract) -> u64 {
        testing_env!(context.attached_deposit(parse_near!("1 N")).build());
        contract.add_proposal(ProposalInput {
            description: "test".to_string(),
            kind: ProposalKind::Transfer {
                token_id: String::from(OLD_BASE_TOKEN),
                receiver_id: accounts(2),
                amount: U128(parse_near!("100 N")),
                msg: None,
            },
        })
    }

    /// Council members with Add, vote on proposal permissions
    /// House CoA with Veto permission
    /// House VB with dissolve permission
    fn house_policy() -> Policy {
        Policy {
            roles: vec![
                RolePermission {
                    name: "council".to_string(),
                    kind: RoleKind::Group(vec![council_member_1(), council_member_2(), council_member_3()].into_iter().collect()),
                    // All actions except RemoveProposal are allowed by council.
                    permissions: vec![
                        "*:AddProposal".to_string(),
                        "*:VoteApprove".to_string(),
                        "*:VoteReject".to_string(),
                        "*:VoteRemove".to_string(),
                        "*:Finalize".to_string(),
                    ]
                    .into_iter()
                    .collect(),
                    vote_policy: HashMap::default(),
                },
                RolePermission {
                    name: "CoA".to_string(),
                    kind: RoleKind::House(vec![council_of_advisors()].into_iter().collect()),
                    permissions: vec![
                        "*:VetoProposal".to_string(),
                    ]
                    .into_iter()
                    .collect(),
                    vote_policy: HashMap::default(),
                },
                RolePermission {
                    name: "VotingBody".to_string(),
                    kind: RoleKind::House(vec![acc_voting_body()].into_iter().collect()),
                    permissions: vec!["*:Dissolve".to_string(),]
                    .into_iter()
                    .collect(),
                    vote_policy: HashMap::default(),
                },
            ],
            default_vote_policy: VotePolicy::default(),
            proposal_bond: U128(10u128.pow(24)),
            proposal_period: U64::from(1_000_000_000 * 60 * 60 * 24 * 7),
            bounty_bond: U128(10u128.pow(24)),
            bounty_forgiveness_period: U64::from(1_000_000_000 * 60 * 60 * 24),
        }
    }

    /// Add voting_body with Dissolve permission
    /// Add CoA with Veto permission
    fn setup_ctr() -> (VMContext, Contract, u64) {
        let mut context = VMContextBuilder::new();
        let mut contract = Contract::new(
            Config::test_config(),
            policy::VersionedPolicy::Current(house_policy()),
            ndc_trust()
        );
        testing_env!(context.predecessor_account_id(council_member_1()).build());
        let id = create_proposal(&mut context, &mut contract);
        (context.build(), contract, id)
    } 

    #[test]
    fn test_basics() {
        let mut context = VMContextBuilder::new();
        testing_env!(context.predecessor_account_id(accounts(1)).build());
        let mut contract = Contract::new(
            Config::test_config(),
            VersionedPolicy::Default(vec![accounts(1)]),
            ndc_trust()
        );
        let id = create_proposal(&mut context, &mut contract);
        assert_eq!(contract.get_proposal(id).proposal.description, "test");
        assert_eq!(contract.get_proposals(0, 10).len(), 1);

        let id = create_proposal(&mut context, &mut contract);
        contract.act_proposal(id, Action::VoteApprove, None);
        assert_eq!(
            contract.get_proposal(id).proposal.status,
            ProposalStatus::Approved
        );

        let id = create_proposal(&mut context, &mut contract);
        // proposal expired, finalize.
        testing_env!(context
            .block_timestamp(1_000_000_000 * 24 * 60 * 60 * 8)
            .build());
        contract.act_proposal(id, Action::Finalize, None);
        assert_eq!(
            contract.get_proposal(id).proposal.status,
            ProposalStatus::Expired
        );

        // non council adding proposal per default policy.
        testing_env!(context
            .predecessor_account_id(accounts(2))
            .attached_deposit(parse_near!("1 N"))
            .build());
        let _id = contract.add_proposal(ProposalInput {
            description: "test".to_string(),
            kind: ProposalKind::AddMemberToRole {
                member_id: accounts(2),
                role: "council".to_string(),
            },
        });
    }

    #[test]
    #[should_panic(expected = "ERR_PERMISSION_DENIED")]
    fn test_remove_proposal_denied() {
        let mut context = VMContextBuilder::new();
        testing_env!(context.predecessor_account_id(accounts(1)).build());
        let mut contract = Contract::new(
            Config::test_config(),
            VersionedPolicy::Default(vec![accounts(1)]),
            ndc_trust()
        );
        let id = create_proposal(&mut context, &mut contract);
        assert_eq!(contract.get_proposal(id).proposal.description, "test");
        contract.act_proposal(id, Action::RemoveProposal, None);
    }

    #[test]
    fn test_remove_proposal_allowed() {
        let mut context = VMContextBuilder::new();
        testing_env!(context.predecessor_account_id(accounts(1)).build());
        let mut policy = VersionedPolicy::Default(vec![accounts(1)]).upgrade();
        policy.to_policy_mut().roles[1]
            .permissions
            .insert("*:RemoveProposal".to_string());
        let mut contract = Contract::new(Config::test_config(), policy, accounts(1));
        let id = create_proposal(&mut context, &mut contract);
        assert_eq!(contract.get_proposal(id).proposal.description, "test");
        contract.act_proposal(id, Action::RemoveProposal, None);
        assert_eq!(contract.get_proposals(0, 10).len(), 0);
    }

    #[test]
    fn test_vote_expired_proposal() {
        let mut context = VMContextBuilder::new();
        testing_env!(context.predecessor_account_id(accounts(1)).build());
        let mut contract = Contract::new(
            Config::test_config(),
            VersionedPolicy::Default(vec![accounts(1)]),
            ndc_trust()
        );
        let id = create_proposal(&mut context, &mut contract);
        testing_env!(context
            .block_timestamp(1_000_000_000 * 24 * 60 * 60 * 8)
            .build());
        contract.act_proposal(id, Action::VoteApprove, None);
    }

    #[test]
    #[should_panic(expected = "ERR_ALREADY_VOTED")]
    fn test_vote_twice() {
        let mut context = VMContextBuilder::new();
        testing_env!(context.predecessor_account_id(accounts(1)).build());
        let mut contract = Contract::new(
            Config::test_config(),
            VersionedPolicy::Default(vec![accounts(1), accounts(2)]),
            ndc_trust()
        );
        let id = create_proposal(&mut context, &mut contract);
        contract.act_proposal(id, Action::VoteApprove, None);
        contract.act_proposal(id, Action::VoteApprove, None);
    }

    #[test]
    fn test_add_to_missing_role() {
        let mut context = VMContextBuilder::new();
        testing_env!(context.predecessor_account_id(accounts(1)).build());
        let mut contract = Contract::new(
            Config::test_config(),
            VersionedPolicy::Default(vec![accounts(1)]),
            ndc_trust()
        );
        testing_env!(context.attached_deposit(parse_near!("1 N")).build());
        let id = contract.add_proposal(ProposalInput {
            description: "test".to_string(),
            kind: ProposalKind::AddMemberToRole {
                member_id: accounts(2),
                role: "missing".to_string(),
            },
        });
        contract.act_proposal(id, Action::VoteApprove, None);
        let x = contract.get_policy();
        // still 2 roles: all and council.
        assert_eq!(x.roles.len(), 2);
    }

    #[test]
    #[should_panic(expected = "ERR_INVALID_POLICY")]
    fn test_fails_adding_invalid_policy() {
        let mut context = VMContextBuilder::new();
        testing_env!(context.predecessor_account_id(accounts(1)).build());
        let mut contract = Contract::new(
            Config::test_config(),
            VersionedPolicy::Default(vec![accounts(1)]),
            ndc_trust()
        );
        testing_env!(context.attached_deposit(parse_near!("1 N")).build());
        let _id = contract.add_proposal(ProposalInput {
            description: "test".to_string(),
            kind: ProposalKind::ChangePolicy {
                policy: VersionedPolicy::Default(vec![]),
            },
        });
    }

    #[test]
    #[should_panic(expected = "ERR_NO_PROPOSAL")]
    fn test_veto_hook() {
        let (mut context, mut contract, id)= setup_ctr();
        assert_eq!(contract.get_proposal(id).id, id);

        context.predecessor_account_id = council_of_advisors();
        testing_env!(context);
        contract.veto(id);

        contract.get_proposal(id);
    }

    #[test]
    #[should_panic(expected = "not authorized")]
    fn test_veto_hook_unauthorised() {
        let (_, mut contract, id)= setup_ctr();
        assert_eq!(contract.get_proposal(id).id, id);
        contract.veto(id);
    }

    #[test]
    #[should_panic(expected = "ERR_PERMISSION_DENIED")]
    fn test_dissolve_hook() {
        let (mut context, mut contract, id)= setup_ctr();
        assert_eq!(contract.get_proposal(id).id, id);

        let mut res = contract.policy.get().unwrap().to_policy();
        assert_eq!(res.roles.is_empty(), false);

        context.predecessor_account_id = acc_voting_body();
        testing_env!(context.clone());
        contract.dissolve();
        res = contract.policy.get().unwrap().to_policy();
        assert_eq!(res.roles.is_empty(), true);

        context.predecessor_account_id = council_member_1();
        context.attached_deposit = parse_near!("1 N");
        testing_env!(context);

        // Should panic because dao is dissolved
        contract.add_proposal(ProposalInput {
            description: "test".to_string(),
            kind: ProposalKind::AddMemberToRole {
                member_id: accounts(2),
                role: "Council".to_string(),
            },
        });
    }
}

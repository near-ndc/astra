use std::str::FromStr;

use astra::{Action, ProposalInput, ProposalKind, OldAccountId, OLD_BASE_TOKEN, Bounty};
use near_sdk::{serde_json::json, Balance, AccountId, json_types::{U128, U64}, ONE_NEAR, env};
// #![allow(dead_code)]
// pub use near_sdk::json_types::{Base64VecU8, U64};
// use near_sdk::{env, AccountId, Balance};
// use near_sdk_sim::transaction::ExecutionStatus;
// use near_sdk_sim::{
//     call, deploy, init_simulator, to_yocto, ContractAccount, ExecutionResult, UserAccount,
// };
use workspaces::{Contract, Account, Worker, DevNetwork, types::{SecretKey, KeyType}, network::Sandbox, result::ExecutionSuccess};
// use near_sdk::json_types::U128;
// use astra_staking::ContractContract as StakingContract;
// use astra::{
//     Action, Bounty, Config, ContractContract as DAOContract, OldAccountId, ProposalInput,
//     ProposalKind, VersionedPolicy, OLD_BASE_TOKEN,
// };
// use astra_factory::AstraFactoryContract as FactoryContract;
// use test_token::ContractContract as TestTokenContract;

// near_sdk_sim::lazy_static_include::lazy_static_include_bytes! {
//     FACTORY_WASM_BYTES => "../astra-factory/res/astra_factory.wasm",
//     DAO_WASM_BYTES => "res/astra.wasm",
//     TEST_TOKEN_WASM_BYTES => "../test-token/res/test_token.wasm",
//     STAKING_WASM_BYTES => "../astra-staking/res/astra_staking.wasm",
// }

// type Contract = ContractAccount<DAOContract>;

pub fn base_token() -> Option<AccountId> {
    None
}

// pub fn should_fail(r: ExecutionResult) {
//     match r.status() {
//         ExecutionStatus::Failure(_) => {}
//         _ => panic!("Should fail"),
//     }
// }

// pub async fn setup_factory(root: &UserAccount) -> ContractAccount<FactoryContract> {
//     let worker = workspaces::sandbox().await?;
//     let contract = worker.dev_deploy(include_bytes!("../../../res/astra_factory.wasm")).await?;
//     deploy!(
//         contract: FactoryContract,
//         contract_id: "factory".to_string(),
//         bytes: &FACTORY_WASM_BYTES,
//         signer_account: root,
//         deposit: to_yocto("500"),
//     )
// }

// pub fn setup_dao() -> (UserAccount, Contract) {
//     let root = init_simulator(None);
//     let config = Config {
//         name: "test".to_string(),
//         purpose: "to test".to_string(),
//         metadata: Base64VecU8(vec![]),
//     };
//     let dao = deploy!(
//         contract: DAOContract,
//         contract_id: "dao".to_string(),
//         bytes: &DAO_WASM_BYTES,
//         signer_account: root,
//         deposit: to_yocto("200"),
//         init_method: new(config, VersionedPolicy::Default(vec![root.account_id.clone()]))
//     );
//     (root, dao)
// }

// pub fn setup_test_token(root: &UserAccount) -> ContractAccount<TestTokenContract> {
//     deploy!(
//         contract: TestTokenContract,
//         contract_id: "test_token".to_string(),
//         bytes: &TEST_TOKEN_WASM_BYTES,
//         signer_account: root,
//         deposit: to_yocto("200"),
//         init_method: new()
//     )
// }

// pub fn setup_staking(root: &UserAccount) -> ContractAccount<StakingContract> {
//     deploy!(
//         contract: StakingContract,
//         contract_id: "staking".to_string(),
//         bytes: &STAKING_WASM_BYTES,
//         signer_account: root,
//         deposit: to_yocto("100"),
//         init_method: new("dao".parse().unwrap(), "test_token".parse::<AccountId>().unwrap(), U64(100_000_000_000))
//     )
// }

// pub fn add_proposal(
//     root: &UserAccount,
//     dao: &Contract,
//     proposal: ProposalInput,
// ) -> ExecutionResult {
//     call!(root, dao.add_proposal(proposal), deposit = to_yocto("1"))
// }

// pub fn add_member_proposal(
//     root: &UserAccount,
//     dao: &Contract,
//     member_id: AccountId,
// ) -> ExecutionResult {
//     add_proposal(
//         root,
//         dao,
//         ProposalInput {
//             description: "test".to_string(),
//             kind: ProposalKind::AddMemberToRole {
//                 member_id: member_id,
//                 role: "council".to_string(),
//             },
//         },
//     )
// }

pub async fn add_transfer_proposal(
    root: Account,
    dao: &Contract,
    token_id: Option<AccountId>,
    receiver_id: AccountId,
    amount: Balance,
    msg: Option<String>,
) -> anyhow::Result<()> {
    let proposal = ProposalInput {
        description: "test".to_string(),
        kind: ProposalKind::Transfer {
            token_id: convert_new_to_old_token(token_id),
            receiver_id,
            amount: U128(amount),
            msg,
        },
    };
    let res = root
    .call(dao.id(), "add_proposal")
    .args_json(json!({"proposal": proposal}))
    .max_gas()
    .deposit(ONE_NEAR)
    .transact()
    .await?;
    assert!(res.is_success(), "{:?}", res);

    Ok(())
}

pub async fn add_bounty_proposal(root: Account, dao: &Contract) -> anyhow::Result<u64> {
    let proposal = ProposalInput {
        description: "test".to_string(),
        kind: ProposalKind::AddBounty {
            bounty: Bounty {
                description: "test bounty".to_string(),
                token: String::from(OLD_BASE_TOKEN),
                amount: U128(ONE_NEAR * 10),
                times: 3,
                max_deadline: U64(env::block_timestamp() + 10_000_000_000),
            },
        },
    };
    let res = root
        .call(dao.id(), "add_proposal")
        .args_json(json!({"proposal": proposal}))
        .max_gas()
        .deposit(ONE_NEAR)
        .transact()
        .await?;
    assert!(res.is_success(), "{:?}", res);

    Ok(res.json()?)
}

pub async fn vote(users: Vec<Account>, dao: &Contract, proposal_id: u64) -> anyhow::Result<()> {
    for user in users.into_iter() {
        let res = user
            .call(dao.id(), "act_proposal")
            .args_json(json!({"id": proposal_id, "action": Action::VoteApprove}))
            .max_gas()
            .transact()
            .await?;
        assert!(res.is_success(), "{:?}", res);
    }
    Ok(())
}

pub fn convert_new_to_old_token(new_account_id: Option<AccountId>) -> OldAccountId {
    if new_account_id.is_none() {
        return String::from(OLD_BASE_TOKEN);
    }
    new_account_id.unwrap().to_string()
}


// Generate user sub-account
pub async fn gen_user_account<T>(worker: &Worker<T>, account_id: &str) -> anyhow::Result<Account>
where
    T: DevNetwork + Send + Sync,
{
    let id = workspaces::AccountId::from_str(account_id)?;
    let sk = SecretKey::from_random(KeyType::ED25519);

    let account = worker.create_tla(id, sk).await?.into_result()?;

    Ok(account)
}

pub async fn transfer_near(
    worker: &Worker<Sandbox>,
    account_id: &workspaces::AccountId,
    deposit: Balance,
) -> anyhow::Result<ExecutionSuccess> {
    Ok(worker
        .root_account()?
        .transfer_near(account_id, deposit)
        .await?
        .into_result()?)
}
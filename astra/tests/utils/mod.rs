use std::str::FromStr;

use anyhow::Ok;
use astra::{Action, ProposalInput, ProposalKind, OldAccountId, OLD_BASE_TOKEN, Bounty, Config, VersionedPolicy};
use near_sdk::{serde_json::json, Balance, AccountId, json_types::{U128, U64, Base64VecU8}, ONE_NEAR, env};
use workspaces::{AccountId as WorkAccountId, Contract, Account, Worker, DevNetwork, types::{SecretKey, KeyType}, network::Sandbox, result::ExecutionSuccess};

pub fn base_token() -> Option<AccountId> {
    None
}

pub async fn setup_dao() -> anyhow::Result<(Account, Contract, Worker<Sandbox>)> {
    let worker = workspaces::sandbox().await?;
    let dao_contract = worker.dev_deploy(include_bytes!("../../../res/astra.wasm")).await?;
    let root = worker.dev_create_account().await?;
    let config = Config {
        name: "test".to_string(),
        purpose: "to test".to_string(),
        metadata: Base64VecU8(vec![]),
    };
    // initialize contract
    let root_near_account: AccountId = root.id().parse().unwrap();
    let res1 = dao_contract
        .call("new")
        .args_json(json!({
            "config": config, "policy": VersionedPolicy::Default(vec![root_near_account.clone()]),
            "trust": root_near_account
        }))
        .max_gas()
        .transact().await?;
    assert!(res1.is_success(), "{:?}", res1);
    Ok((root, dao_contract, worker))
}

pub async fn setup_test_token(worker: Worker<Sandbox>) -> anyhow::Result<(Contract, Worker<Sandbox>)> {
    let test_token = worker.dev_deploy(include_bytes!("../../../res/test_token.wasm")).await?;
    let res1 = test_token
        .call("new")
        .max_gas()
        .transact().await?;
    assert!(res1.is_success(), "{:?}", res1);

    Ok((test_token, worker))
}

pub async fn setup_staking(token_id: WorkAccountId, dao: WorkAccountId, worker: Worker<Sandbox>) -> anyhow::Result<(Contract, Worker<Sandbox>)> {
    let staking = worker.dev_deploy(include_bytes!("../../../res/astra_staking.wasm")).await?;
    let res1 = staking
        .call("new")
        .args_json(json!({
            "owner_id": dao, "token_id": token_id,
            "unstake_period": U64(100_000_000_000)
        }))
        .max_gas()
        .transact().await?;
    assert!(res1.is_success(), "{:?}", res1);

    Ok((staking, worker))
}

pub async fn add_member_proposal(
    root: Account,
    dao: &Contract,
    member_id: AccountId,
) -> anyhow::Result<()> {
    let proposal = ProposalInput {
        description: "test".to_string(),
        kind: ProposalKind::AddMemberToRole {
            member_id,
            role: "council".to_string(),
        },
        category: None
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
        category: None
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
        category: None
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
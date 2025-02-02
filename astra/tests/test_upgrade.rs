use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use std::str::FromStr;

use crate::utils::*;
mod utils;
use workspaces::{AccountId as WorkAccountId};
use astra::{Config, VersionedPolicy, ProposalInput, ProposalKind, Action};
use near_sdk::{serde_json::json, json_types::{Base64VecU8, Base58CryptoHash}, AccountId, ONE_NEAR};

#[tokio::test]
async fn test_upgrade_using_factory() -> anyhow::Result<()> {
    let worker = workspaces::sandbox().await?;
    let factory_contract = worker.dev_deploy(include_bytes!("../../res/astra_factory.wasm")).await?;
    let root = worker.dev_create_account().await?;
    // initialize contract
    let res1 = factory_contract
        .call("new")
        .args_json(json!({}))
        .max_gas()
        .transact();

    assert!(res1.await?.is_success());

    let config = Config {
        name: "testdao".to_string(),
        purpose: "to test".to_string(),
        metadata: Base64VecU8(vec![]),
    };
    let root_near_account: AccountId = root.id().parse().unwrap();

    let policy = VersionedPolicy::Default(vec![root_near_account.clone()]);
    let params = json!({ "config": config, "policy": policy, "trust": root_near_account})
        .to_string()
        .into_bytes();

    let res2 = root
        .call(factory_contract.id(), "create")
        .args_json((AccountId::new_unchecked("testdao".to_string()), Base64VecU8(params)))
        .gas(300_000_000_000_000)
        .deposit(ONE_NEAR * 10)
        .transact()
        .await?;
    assert!(res2.is_success());

    let dao_account_id = AccountId::new_unchecked("testdao.".to_string() + factory_contract.id());
    let dao_list: Vec<AccountId>= factory_contract
        .call("get_dao_list")
        .view()
        .await?
        .json()?;
    assert_eq!(dao_list, vec![dao_account_id.clone()]);

    let dao = WorkAccountId::from_str(dao_account_id.as_ref())?;

    let hash: Base58CryptoHash= factory_contract
        .call("get_default_code_hash")
        .view()
        .await?
        .json()?;

    let proposal = ProposalInput {
        description: "proposal to test".to_string(),
        kind: ProposalKind::UpgradeSelf { hash },
        category: None
    };
    let res = root
        .call(&dao, "add_proposal")
        .args_json(json!({"proposal": proposal}))
        .max_gas()
        .deposit(ONE_NEAR)
        .transact()
        .await?;
    assert!(res.is_success(), "{:?}", res);
    
    let res = root
        .call(&dao, "act_proposal")
        .args_json(json!({"id": 0, "action": Action::VoteApprove}))
        .max_gas()
        .transact()
        .await?;
    assert!(res.is_success(), "{:?}", res);

    Ok(())
}

#[derive(BorshSerialize, BorshDeserialize)]
struct NewArgs {
    owner_id: AccountId,
    exchange_fee: u32,
    referral_fee: u32,
}

// /// Test that astra can upgrade another contract.
#[tokio::test]
async fn test_upgrade_other() -> anyhow::Result<()> {
    let (root, dao, worker) = setup_dao().await?;
    let _ = transfer_near(&worker, root.id(), ONE_NEAR * 1000).await?;
    let (other_contract, _) = setup_test_token(worker).await?;

    let res = root
        .call(dao.id(), "store_blob")
        .args(include_bytes!("../../res/test_token.wasm").to_vec())
        .max_gas()
        .deposit(ONE_NEAR * 200)
        .transact()
        .await?;
    assert!(res.is_success(), "{:?}", res);
    let hash: Base58CryptoHash = res.json()?; 

    let proposal = ProposalInput {
        description: "test".to_string(),
        kind: ProposalKind::UpgradeRemote {
            receiver_id: other_contract.id().clone().parse().unwrap(),
            method_name: "upgrade".to_string(),
            hash,
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

    vote(vec![root], &dao, 0).await?;

    Ok(())
}

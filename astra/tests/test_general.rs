use std::collections::HashMap;

use near_sdk::json_types::{U128, Base64VecU8, U64};
use near_sdk::serde_json::json;
use near_sdk::{env, AccountId, ONE_NEAR};

use crate::utils::*;
use astra_staking::User;
use astra::{
    default_policy, Action, BountyClaim, BountyOutput, Config, Policy, Proposal, ProposalInput,
    ProposalKind, ProposalOutput, ProposalStatus, RoleKind, RolePermission, VersionedPolicy,
    VotePolicy,
};

mod utils;

fn user(id: u32) -> AccountId {
    format!("user{}.test.near", id).parse().unwrap()
}

#[tokio::test]
async fn test_large_policy() -> anyhow::Result<()> {
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
    let mut policy = default_policy(vec![root_near_account]);
    const NO_OF_COUNCILS: u32 = 10;
    const USERS_PER_COUNCIL: u32 = 100;
    for council_no in 0..NO_OF_COUNCILS {
        let mut council = vec![];
        let user_id_start = council_no * USERS_PER_COUNCIL;
        let user_id_end = user_id_start + USERS_PER_COUNCIL;
        for user_id in user_id_start..user_id_end {
            council.push(user(user_id));
        }

        let role = RolePermission {
            name: format!("council{}", council_no),
            kind: RoleKind::Group(council.into_iter().collect()),
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
        };
        policy.add_or_update_role(&role);
    }

    let params = json!({ "config": config, "policy": policy })
        .to_string()
        .into_bytes();

    let res2 = factory_contract
        .call("create")
        .args_json((AccountId::new_unchecked("testdao".to_string()), Base64VecU8(params)))
        .gas(300_000_000_000_000)
        .deposit(ONE_NEAR * 10)
        .transact()
        .await?;
    assert!(res2.is_success());

    let dao_account_id = AccountId::new_unchecked("testdao.".to_string() + factory_contract.id());

    let dao_list: Vec<AccountId>= factory_contract
        .call("get_dao_list")
        //.args_json([])
        .view()
        .await?
        .json()?;
    assert_eq!(dao_list, vec![dao_account_id.clone()]);

    Ok(())
}

#[tokio::test]
async fn test_multi_council() -> anyhow::Result<()> {
    let (root, dao_contract, worker) = setup_dao().await?;

    let user1 = gen_user_account(&worker, user(1).as_str()).await?;
    let _ = transfer_near(&worker, user1.id(), ONE_NEAR * 50).await?;
    let user2 = gen_user_account(&worker, user(2).as_str()).await?;
    let _ = transfer_near(&worker, user2.id(), ONE_NEAR * 50).await?;
    let user3 = gen_user_account(&worker, user(3).as_str()).await?;
    let _ = transfer_near(&worker, user3.id(), ONE_NEAR * 50).await?;

    let new_policy = Policy {
        roles: vec![
            RolePermission {
                name: "all".to_string(),
                kind: RoleKind::Everyone,
                permissions: vec!["*:AddProposal".to_string()].into_iter().collect(),
                vote_policy: HashMap::default(),
            },
            RolePermission {
                name: "council".to_string(),
                kind: RoleKind::Group(vec![user(1), user(2)].into_iter().collect()),
                permissions: vec!["*:*".to_string()].into_iter().collect(),
                vote_policy: HashMap::default(),
            },
            RolePermission {
                name: "community".to_string(),
                kind: RoleKind::Group(vec![user(1), user(3), user(4)].into_iter().collect()),
                permissions: vec!["*:*".to_string()].into_iter().collect(),
                vote_policy: HashMap::default(),
            },
        ],
        default_vote_policy: VotePolicy::default(),
        proposal_bond: U128(10u128.pow(24)),
        proposal_period: U64::from(1_000_000_000 * 60 * 60 * 24 * 7),
        bounty_bond: U128(10u128.pow(24)),
        bounty_forgiveness_period: U64::from(1_000_000_000 * 60 * 60 * 24),
    };

    let proposal = ProposalInput {
        description: "new policy".to_string(),
        kind: ProposalKind::ChangePolicy {
            policy: VersionedPolicy::Current(new_policy.clone()),
        },
    };
    let res2 = root.call(dao_contract.id(), "add_proposal")
        .args_json(json!({"proposal": proposal}))
        .gas(300_000_000_000_000)
        .deposit(ONE_NEAR)
        .transact()
        .await?;
    assert!(res2.is_success(), "{:?}", res2);

    vote(vec![root.clone()], &dao_contract, 0).await?;

    let policy: Policy = dao_contract.call("get_policy").view().await?.json()?;
    assert_eq!(policy, new_policy);
    add_transfer_proposal(root.clone(), &dao_contract, base_token(), user(1), 1_000_000, None).await?;

    vote(vec![user2], &dao_contract, 1).await?;
    vote(vec![user3], &dao_contract, 1).await?;
    let proposal: Proposal = dao_contract.call("get_proposal").args_json(json!({"id":1})).view().await?.json()?;
    // Votes from members in different councils.
    assert_eq!(proposal.status, ProposalStatus::InProgress);
    // Finish with vote that is in both councils, which approves the proposal.
    vote(vec![user1], &dao_contract, 1).await?;
    let proposal: Proposal = dao_contract.call("get_proposal").args_json(json!({"id":1})).view().await?.json()?;
    assert_eq!(proposal.status, ProposalStatus::Approved);

    Ok(())
}

#[tokio::test]
async fn test_bounty_workflow() -> anyhow::Result<()> {
    let (root, dao_contract, worker) = setup_dao().await?;
    
    let user1 = gen_user_account(&worker, user(1).as_str()).await?;
    let _ = transfer_near(&worker, user1.id(), ONE_NEAR * 900).await?;
    let user2 = gen_user_account(&worker, user(2).as_str()).await?;
    let _ = transfer_near(&worker, user2.id(), ONE_NEAR * 900).await?;

    let mut proposal_id = add_bounty_proposal(root.clone(), &dao_contract).await?;
    assert_eq!(proposal_id, 0);

    vote(vec![root.clone()], &dao_contract, proposal_id).await?;

    let mut bounty_id: u64 = dao_contract.call("get_last_bounty_id").view().await?.json()?;
    bounty_id -= 1u64;

    assert_eq!(bounty_id, 0);
    let bounty: BountyOutput = dao_contract.call("get_bounty")
                .args_json(json!({"id": bounty_id})).view().await?.json()?;
    assert_eq!(
        bounty.bounty.times,
        3
    );

    assert_eq!(ONE_NEAR * 1000, user1.view_account().await?.balance);

    let res = user1
        .call(dao_contract.id(), "bounty_claim")
        .args_json(json!({"id": bounty_id, "deadline": U64::from(0)}))
        .max_gas()
        .deposit(ONE_NEAR)
        .transact()
        .await?;
    assert!(res.is_success(), "{:?}", res);

    assert!(user1.view_account().await?.balance < ONE_NEAR * 999);

    let bounty_claim: Vec<BountyClaim> = dao_contract.call("get_bounty_claims")
                .args_json(json!({"account_id": user1.id()})).view().await?.json()?;
    assert_eq!(
       bounty_claim.len(),
        1
    );

    let bounty_claim: u64 = dao_contract.call("get_bounty_number_of_claims")
            .args_json(json!({"id": bounty_id})).view().await?.json()?;
    assert_eq!(
        bounty_claim,
        1
    );

    let res = user1
        .call(dao_contract.id(), "bounty_giveup")
        .args_json(json!({"id": bounty_id}))
        .max_gas()
        .transact()
        .await?;
    assert!(res.is_success(), "{:?}", res);
    assert!(user1.view_account().await?.balance > ONE_NEAR * 999);

    let bounty_claim: Vec<BountyClaim> = dao_contract.call("get_bounty_claims")
        .args_json(json!({"account_id": user1.id()})).view().await?.json()?;
    assert_eq!(
        bounty_claim.len(),
        0
    );
    let bounty_claim_number: u64 = dao_contract.call("get_bounty_number_of_claims")
        .args_json(json!({"id": bounty_id})).view().await?.json()?;
    assert_eq!(
        bounty_claim_number,
        0
    );

    assert_eq!(ONE_NEAR * 1000, user2.view_account().await?.balance);

    let res = user2
        .call(dao_contract.id(), "bounty_claim")
        .args_json(json!({"id": bounty_id, "deadline": U64(env::block_timestamp() + 5_000_000_000)}))
        .max_gas()
        .deposit(ONE_NEAR)
        .transact()
        .await?;
    assert!(res.is_success(), "{:?}", res);
    assert!(user2.view_account().await?.balance < ONE_NEAR * 999);

    let bounty_claim: Vec<BountyClaim> = dao_contract.call("get_bounty_claims")
        .args_json(json!({"account_id": user2.id()})).view().await?.json()?;
    assert_eq!(
        bounty_claim.len(),
        1
    );
    let bounty_claim_number: u64 = dao_contract.call("get_bounty_number_of_claims")
        .args_json(json!({"id": bounty_id})).view().await?.json()?;
    assert_eq!(
        bounty_claim_number,
        1
    );

    let res = user2
        .call(dao_contract.id(), "bounty_done")
        .args_json(json!({"id": bounty_id, "description": "Bounty is done".to_string()}))
        .max_gas()
        .deposit(ONE_NEAR)
        .transact()
        .await?;
    assert!(res.is_success(), "{:?}", res);
    assert!(user2.view_account().await?.balance < ONE_NEAR * 998);

    let latest_prop_id: u64 = dao_contract.call("get_last_proposal_id").view().await?.json()?;
    proposal_id = latest_prop_id - 1u64;
    assert_eq!(proposal_id, 1);

    let prop_out: ProposalOutput = dao_contract.call("get_proposal")
        .args_json(json!({"id": proposal_id})).view().await?.json()?;
    assert_eq!(
        prop_out
            .proposal
            .kind
            .to_policy_label(),
        "bounty_done"
    );

    vote(vec![root.clone()], &dao_contract, proposal_id).await?;

    assert!(user2.view_account().await?.balance > ONE_NEAR * 999);

    let bounty_claim: Vec<BountyClaim> = dao_contract.call("get_bounty_claims")
        .args_json(json!({"account_id": user2.id()})).view().await?.json()?;
    assert_eq!(
        bounty_claim.len(),
        0
    );
    let bounty_claim_number: u64 = dao_contract.call("get_bounty_number_of_claims")
        .args_json(json!({"id": bounty_id})).view().await?.json()?;
    assert_eq!(
        bounty_claim_number,
        0
    );
    let bounty: BountyOutput = dao_contract.call("get_bounty")
                .args_json(json!({"id": bounty_id})).view().await?.json()?;
    assert_eq!(
        bounty.bounty.times,
        2
    );

    Ok(())
}

#[tokio::test]
async fn test_create_dao_and_use_token() -> anyhow::Result<()> {
    let (root, dao, worker) = setup_dao().await?;
    let user2 = gen_user_account(&worker, user(2).as_str()).await?;
    let _ = transfer_near(&worker, user2.id(), ONE_NEAR * 900).await?;
    let user3 = gen_user_account(&worker, user(3).as_str()).await?;
    let _ = transfer_near(&worker, user3.id(), ONE_NEAR * 900).await?;
    let (test_token, worker) = setup_test_token(worker).await?;
    let (staking, _) = setup_staking(test_token.id().clone(), dao.id().clone(), worker).await?;

    let staking_contract: String = dao.call("get_staking_contract").view().await?.json()?;
    assert!(staking_contract.is_empty());

    let user2_near_account: AccountId = user2.id().parse().unwrap();
    add_member_proposal(root.clone(), &dao, user2_near_account).await?;

    let last_prop: u64 = dao.call("get_last_proposal_id").view().await?.json()?;
    assert_eq!(last_prop, 1);

    // Voting by user who is not member should fail.
    let res = user2.clone()
        .call(dao.id(), "act_proposal")
        .args_json(json!({"id": 0, "action": Action::VoteApprove}))
        .max_gas()
        .transact()
        .await?;
    assert!(res.is_failure(), "{:?}", res);
    //should_fail(call!(user2, dao.act_proposal(0, Action::VoteApprove, None)));
    let res = root.clone()
        .call(dao.id(), "act_proposal")
        .args_json(json!({"id": 0, "action": Action::VoteApprove}))
        .max_gas()
        .transact()
        .await?;
    assert!(res.is_success(), "{:?}", res);
    // voting second time should fail.
    let res = root.clone()
        .call(dao.id(), "act_proposal")
        .args_json(json!({"id": 0, "action": Action::VoteApprove}))
        .max_gas()
        .transact()
        .await?;
    assert!(res.is_failure(), "{:?}", res);

    // Add 3rd member.
    let user3_near_account: AccountId = user3.id().parse().unwrap();

    add_member_proposal(user2.clone(), &dao.clone(), user3_near_account).await?;
    vote(vec![root.clone(), user2.clone()], &dao.clone(), 1).await?;
    let policy: Policy = dao.call("get_policy").view().await?.json()?;
    assert_eq!(policy.roles.len(), 2);
    assert_eq!(
        policy.roles[1].kind,
        RoleKind::Group(
            vec![
                root.id().parse().unwrap(),
                user2.id().parse().unwrap(),
                user3.id().parse().unwrap()
            ]
            .into_iter()
            .collect()
        )
    );

    let proposal = ProposalInput {
        description: "test".to_string(),
        kind: ProposalKind::SetStakingContract {
            staking_id: staking.id().parse().unwrap(),
        },
    };
    let res = user2
        .call(dao.id(), "add_proposal")
        .args_json(json!({"proposal": proposal}))
        .max_gas()
        .deposit(ONE_NEAR)
        .transact()
        .await?;
    assert!(res.is_success(), "{:?}", res);

    vote(vec![user3.clone(), user2.clone()], &dao, 2).await?;

    let staking_contract: String = dao.call("get_staking_contract").view().await?.json()?;
    assert!(!staking_contract.is_empty());

    let prop: Proposal = dao.call("get_proposal").args_json(json!({"id": 2})).view().await?.json()?;
    assert_eq!(
        prop.status,
        ProposalStatus::Approved
    );

    let supply: U128 = staking.call("ft_total_supply").view().await?.json()?;
    assert_eq!(
        supply.0,
        0
    );

    let res = user2
        .call(test_token.id(), "mint")
        .args_json(json!({"account_id": user2.id(), "amount": U128(100 * ONE_NEAR)}))
        .max_gas()
        .transact()
        .await?;
    assert!(res.is_success(), "{:?}", res);

    let res = user2
        .call(test_token.id(), "storage_deposit")
        .args_json(json!({"account_id": staking.id()}))
        .max_gas()
        .deposit(ONE_NEAR)
        .transact()
        .await?;
    assert!(res.is_success(), "{:?}", res);

    let res = user2
        .call(staking.id(), "storage_deposit")
        .args_json(json!({}))
        .max_gas()
        .deposit(ONE_NEAR)
        .transact()
        .await?;
    assert!(res.is_success(), "{:?}", res);

    let res = user2
        .call(test_token.id(), "ft_transfer_call")
        .args_json(json!({"receiver_id": staking.id(), "amount": U128(10 * ONE_NEAR), "msg": "".to_string()}))
        .max_gas()
        .deposit(1)
        .transact()
        .await?;
    assert!(res.is_success(), "{:?}", res);

    let supply: U128 = staking.call("ft_total_supply").view().await?.json()?;
    assert_eq!(
        supply.0,
        10 * ONE_NEAR
    );

    let bal: U128 = staking.call("ft_balance_of").args_json(json!({"account_id": user2.id()})).view().await?.json()?;
    assert_eq!(
        bal.0,
        10 * ONE_NEAR
    );

    let bal: U128 = test_token.call("ft_balance_of").args_json(json!({"account_id": user2.id()})).view().await?.json()?;
    assert_eq!(
        bal.0,
        90 * ONE_NEAR
    );
    let res = user2
        .call(staking.id(), "withdraw")
        .args_json(json!({"amount": U128(5 * ONE_NEAR)}))
        .max_gas()
        .transact()
        .await?;
    assert!(res.is_success(), "{:?}", res);
    let supply: U128 = staking.call("ft_total_supply").view().await?.json()?;
    assert_eq!(
        supply.0,
        5 * ONE_NEAR
    );
    let bal: U128 = test_token.call("ft_balance_of").args_json(json!({"account_id": user2.id()})).view().await?.json()?;
    assert_eq!(
        bal.0,
        95 * ONE_NEAR
    );

    let res = user2
        .call(staking.id(), "delegate")
        .args_json(json!({"account_id": user2.id(), "amount": U128(5 * ONE_NEAR)}))
        .max_gas()
        .transact()
        .await?;
    assert!(res.is_success(), "{:?}", res);

    let res = user2
        .call(staking.id(), "undelegate")
        .args_json(json!({"account_id": user2.id(), "amount": U128(ONE_NEAR)}))
        .max_gas()
        .transact()
        .await?;
    assert!(res.is_success(), "{:?}", res);
    // should fail right after undelegation as need to wait for voting period before can delegate again.
    let res = user2
        .call(staking.id(), "delegate")
        .args_json(json!({"account_id": user2.id(), "amount": U128(ONE_NEAR)}))
        .max_gas()
        .transact()
        .await?;
    assert!(res.is_failure(), "{:?}", res);
    let user: User = staking.call("get_user").args_json(json!({"account_id": user2.id()})).view().await?.json()?;
    assert_eq!(
        user.delegated_amounts,
        vec![(user2.id().parse().unwrap(), U128(4 * ONE_NEAR))]
    );

    let supply: U128 = dao.call("delegation_total_supply").view().await?.json()?;
    assert_eq!(
        supply.0,
        4 * ONE_NEAR
    );
    let bal: U128 = dao.call("delegation_balance_of").args_json(json!({"account_id": user2.id()})).view().await?.json()?;
    assert_eq!(
        bal.0,
        4 * ONE_NEAR
    );

    Ok(())
}

/// Test various cases that must fail.
#[tokio::test]
async fn test_failurestest_create_dao_and_use_token() -> anyhow::Result<()> {
    let (root, dao, _) = setup_dao().await?;

    let proposal = ProposalInput {
        description: "test".to_string(),
        kind: ProposalKind::Transfer {
            token_id: convert_new_to_old_token(base_token()),
            receiver_id: user(1),
            amount: U128(1_000_000),
            msg: Some("some".to_string()),
        },
    };
    let res = root
        .call(dao.id(), "add_proposal")
        .args_json(json!({"proposal": proposal}))
        .max_gas()
        .transact()
        .await?;
    assert!(res.is_failure(), "{:?}", res);

    Ok(())
}

// Test payments that fail
#[tokio::test]
async fn test_payment_failures() -> anyhow::Result<()> {
    let (root, dao, worker) = setup_dao().await?;
    let user1 = gen_user_account(&worker, user(1).as_str()).await?;
    let _ = transfer_near(&worker, user1.id(), ONE_NEAR * 900).await?;
    let whale = gen_user_account(&worker, user(2).as_str()).await?;
    let _ = transfer_near(&worker, whale.id(), ONE_NEAR * 900).await?;

    // Add user1
    add_member_proposal(root.clone(), &dao, user1.id().parse().unwrap()).await?;
    vote(vec![root.clone()], &dao, 0).await?;

    // Set up fungible tokens and give 5 to the dao
    let (test_token, _) = setup_test_token(worker).await?;
    let res = dao.as_account()
        .call(test_token.id(), "mint")
        .args_json(json!({"account_id": dao.id(), "amount": U128(5)}))
        .max_gas()
        .transact()
        .await?;
    assert!(res.is_success(), "{:?}", res);

    let res = user1
        .call(test_token.id(), "storage_deposit")
        .args_json(json!({"account_id": user1.id(), "registration_only": true}))
        .max_gas()
        .deposit(ONE_NEAR * 125)
        .transact()
        .await?;
    assert!(res.is_success(), "{:?}", res);

    // Attempt to transfer more than it has
    add_transfer_proposal(
        root.clone(),
        &dao,
        Some(test_token.id().parse().unwrap()),
        user(1),
        10,
        None,
    ).await?;

    // Vote in the transfer
    vote(vec![root.clone(), user1.clone()], &dao, 1).await?;
    let mut proposal: Proposal = dao.call("get_proposal").args_json(json!({"id": 1})).view().await?.json()?;

    assert_eq!(proposal.status, ProposalStatus::Failed);

    // Set up benefactor whale who will donate the needed tokens
    let res = whale
        .call(test_token.id(), "mint")
        .args_json(json!({"account_id": whale.id(), "amount": U128(6_000_000_000)}))
        .max_gas()
        .transact()
        .await?;
    assert!(res.is_success(), "{:?}", res);

    let res = whale
        .call(test_token.id(), "ft_transfer")
        .args_json(json!({"receiver_id": dao.id(), "amount": U128::from(1000), "msg": "Heard you're in a pinch, let me help.".to_string()}))
        .max_gas()
        .deposit(1)
        .transact()
        .await?;
    assert!(res.is_success(), "{:?}", res);

    // Council member retries payment via an action
    let res = root
            .call(dao.id(), "act_proposal")
            .args_json(json!({"id": 1, "action": Action::Finalize, "msg": "Sorry! We topped up our tokens. Thanks.".to_string()}))
            .max_gas()
            .transact()
            .await?;
    assert!(res.is_success(), "{:?}", res);

    proposal = dao.call("get_proposal").args_json(json!({"id": 1})).view().await?.json()?;
    assert_eq!(
        proposal.status,
        ProposalStatus::Approved,
        "Did not return to approved status."
    );

    Ok(())
}

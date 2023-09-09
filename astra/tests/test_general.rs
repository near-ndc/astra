use std::collections::HashMap;

use near_sdk::json_types::{U128, Base64VecU8, U64};
use near_sdk::serde_json::json;
use near_sdk::{env, AccountId, ONE_NEAR};
use workspaces::{Account, Contract, DevNetwork, Worker, AccountId as WorkAccountId};

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
    let worker = workspaces::sandbox().await?;
    let dao_contract = worker.dev_deploy(include_bytes!("../../res/astra.wasm")).await?;
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
            "config": config, "policy": VersionedPolicy::Default(vec![root_near_account])
        }))
        .max_gas()
        .transact();
    assert!(res1.await?.is_success());

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
    let worker = workspaces::sandbox().await?;
    let dao_contract = worker.dev_deploy(include_bytes!("../../res/astra.wasm")).await?;
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
            "config": config, "policy": VersionedPolicy::Default(vec![root_near_account])
        }))
        .max_gas()
        .transact();
    assert!(res1.await?.is_success());
    // TODO: add setup_dao
    
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
    let (root, dao) = setup_dao();
    let user2 = root.create_user(user(2), to_yocto("1000"));
    let user3 = root.create_user(user(3), to_yocto("1000"));
    let test_token = setup_test_token(&root);
    let staking = setup_staking(&root);

    assert!(view!(dao.get_staking_contract())
        .unwrap_json::<String>()
        .is_empty());
    add_member_proposal(&root, &dao, user2.account_id.clone()).assert_success();
    assert_eq!(view!(dao.get_last_proposal_id()).unwrap_json::<u64>(), 1);
    // Voting by user who is not member should fail.
    should_fail(call!(user2, dao.act_proposal(0, Action::VoteApprove, None)));
    call!(root, dao.act_proposal(0, Action::VoteApprove, None)).assert_success();
    // voting second time should fail.
    should_fail(call!(root, dao.act_proposal(0, Action::VoteApprove, None)));
    // Add 3rd member.
    add_member_proposal(&user2, &dao, user3.account_id.clone()).assert_success();
    vote(vec![&root, &user2], &dao, 1);
    let policy = view!(dao.get_policy()).unwrap_json::<Policy>();
    assert_eq!(policy.roles.len(), 2);
    assert_eq!(
        policy.roles[1].kind,
        RoleKind::Group(
            vec![
                root.account_id.clone(),
                user2.account_id.clone(),
                user3.account_id.clone()
            ]
            .into_iter()
            .collect()
        )
    );
    add_proposal(
        &user2,
        &dao,
        ProposalInput {
            description: "test".to_string(),
            kind: ProposalKind::SetStakingContract {
                staking_id: "staking".parse().unwrap(),
            },
        },
    )
    .assert_success();
    vote(vec![&user3, &user2], &dao, 2);
    assert!(!view!(dao.get_staking_contract())
        .unwrap_json::<String>()
        .is_empty());
    assert_eq!(
        view!(dao.get_proposal(2)).unwrap_json::<Proposal>().status,
        ProposalStatus::Approved
    );

    staking
        .user_account
        .view_method_call(staking.contract.ft_total_supply());
    assert_eq!(
        view!(staking.ft_total_supply()).unwrap_json::<U128>().0,
        to_yocto("0")
    );
    call!(
        user2,
        test_token.mint(user2.account_id.clone(), U128(to_yocto("100")))
    )
    .assert_success();
    call!(
        user2,
        test_token.storage_deposit(Some(staking.account_id()), None),
        deposit = to_yocto("1")
    )
    .assert_success();
    call!(
        user2,
        staking.storage_deposit(None, None),
        deposit = to_yocto("1")
    );
    call!(
        user2,
        test_token.ft_transfer_call(
            staking.account_id(),
            U128(to_yocto("10")),
            None,
            "".to_string()
        ),
        deposit = 1
    )
    .assert_success();
    assert_eq!(
        view!(staking.ft_total_supply()).unwrap_json::<U128>().0,
        to_yocto("10")
    );
    let user2_id = user2.account_id.clone();
    assert_eq!(
        view!(staking.ft_balance_of(user2_id.clone()))
            .unwrap_json::<U128>()
            .0,
        to_yocto("10")
    );
    assert_eq!(
        view!(test_token.ft_balance_of(user2_id.clone()))
            .unwrap_json::<U128>()
            .0,
        to_yocto("90")
    );
    call!(user2, staking.withdraw(U128(to_yocto("5")))).assert_success();
    assert_eq!(
        view!(staking.ft_total_supply()).unwrap_json::<U128>().0,
        to_yocto("5")
    );
    assert_eq!(
        view!(test_token.ft_balance_of(user2_id.clone()))
            .unwrap_json::<U128>()
            .0,
        to_yocto("95")
    );
    call!(
        user2,
        staking.delegate(user2_id.clone(), U128(to_yocto("5")))
    )
    .assert_success();
    call!(
        user2,
        staking.undelegate(user2_id.clone(), U128(to_yocto("1")))
    )
    .assert_success();
    // should fail right after undelegation as need to wait for voting period before can delegate again.
    should_fail(call!(
        user2,
        staking.delegate(user2_id.clone(), U128(to_yocto("1")))
    ));
    let user = view!(staking.get_user(user2_id.clone())).unwrap_json::<User>();
    assert_eq!(
        user.delegated_amounts,
        vec![(user2_id.clone(), U128(to_yocto("4")))]
    );
    assert_eq!(
        view!(dao.delegation_total_supply()).unwrap_json::<U128>().0,
        to_yocto("4")
    );
    assert_eq!(
        view!(dao.delegation_balance_of(user2_id.clone()))
            .unwrap_json::<U128>()
            .0,
        to_yocto("4")
    );
}

// /// Test various cases that must fail.
// #[test]
// fn test_failures() {
//     let (root, dao) = setup_dao();
//     should_fail(add_transfer_proposal(
//         &root,
//         &dao,
//         base_token(),
//         user(1),
//         1_000_000,
//         Some("some".to_string()),
//     ));
// }

// /// Test payments that fail
// #[test]
// fn test_payment_failures() {
//     let (root, dao) = setup_dao();
//     let user1 = root.create_user(user(1), to_yocto("1000"));
//     let whale = root.create_user(user(2), to_yocto("1000"));

//     // Add user1
//     add_member_proposal(&root, &dao, user1.account_id.clone()).assert_success();
//     vote(vec![&root], &dao, 0);

//     // Set up fungible tokens and give 5 to the dao
//     let test_token = setup_test_token(&root);
//     call!(
//         dao.user_account,
//         test_token.mint(dao.user_account.account_id.clone(), U128(5))
//     )
//     .assert_success();
//     call!(
//         user1,
//         test_token.storage_deposit(Some(user1.account_id.clone()), Some(true)),
//         deposit = to_yocto("125")
//     )
//     .assert_success();

//     // Attempt to transfer more than it has
//     add_transfer_proposal(
//         &root,
//         &dao,
//         Some(test_token.account_id()),
//         user(1),
//         10,
//         None,
//     )
//     .assert_success();

//     // Vote in the transfer
//     vote(vec![&root, &user1], &dao, 1);
//     let mut proposal = view!(dao.get_proposal(1)).unwrap_json::<Proposal>();
//     assert_eq!(proposal.status, ProposalStatus::Failed);

//     // Set up benefactor whale who will donate the needed tokens
//     call!(
//         whale,
//         test_token.mint(whale.account_id.clone(), U128(6_000_000_000))
//     )
//     .assert_success();
//     call!(
//         whale,
//         test_token.ft_transfer(
//             dao.account_id(),
//             U128::from(1000),
//             Some("Heard you're in a pinch, let me help.".to_string())
//         ),
//         deposit = 1
//     )
//     .assert_success();

//     // Council member retries payment via an action
//     call!(
//         root,
//         dao.act_proposal(
//             1,
//             Action::Finalize,
//             Some("Sorry! We topped up our tokens. Thanks.".to_string())
//         )
//     )
//     .assert_success();

//     proposal = view!(dao.get_proposal(1)).unwrap_json::<Proposal>();
//     assert_eq!(
//         proposal.status,
//         ProposalStatus::Approved,
//         "Did not return to approved status."
//     );
// }

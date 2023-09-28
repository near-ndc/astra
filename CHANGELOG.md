<!-- markdownlint-disable MD013 -->
<!-- markdownlint-disable MD024 -->

<!--
Changelogs are for humans, not machines.
There should be an entry for every single version.
The same types of changes should be grouped.
The latest version comes first.
The release date of each version is displayed.

Usage:

Change log entries are to be added to the Unreleased section. Example entry:

* [#<PR-number>](https://github.com/umee-network/umee/pull/<PR-number>) <description>

-->

# CHANGELOG

## Unreleased

+ Update repo to the latest near-sdk and related deps
+ Integrate hooks
+ Add option to act_proposal to not execute the proposal
+ Add events to veto and dissolve hooks
+ Integrate cooldown

### Features

New methods:

- `veto_hook`: Vetos any proposal.(must be called by authority with permission)
- `dissolve_hook`: Dissolves the DAO by removing all members, closing all active proposals and returning bonds.

Extended types:

- ProposalStatus: `Executed`
- Action: `Veto` and `Dissolve`

New types:

- `ContractStatus`: Active or Dissolved

### Breaking Changes

- B...

### Bug Fixes

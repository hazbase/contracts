// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.23;

import '@openzeppelin/contracts/access/AccessControl.sol';

contract MockGovernorBasic is AccessControl {
    bytes32 public constant META_ROLE = keccak256('META_ROLE');

    enum IProposalState {
        Pending,
        Active,
        Canceled,
        Defeated,
        Succeeded,
        Queued,
        Expired,
        Executed
    }

    struct ProposalDetails {
        address proposer;
        address[] targets;
        uint256[] values;
        bytes[] calldatas;
        uint64 start;
        uint64 end;
        string description;
    }

    struct ProposalTally {
        uint256 yesVotes;
        uint256 noVotes;
        uint256 supply;
    }

    mapping(uint256 => ProposalDetails) private _details;
    mapping(uint256 => ProposalTally) private _tallies;
    mapping(uint256 => IProposalState) private _states;

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    function getVotes(address, uint256) external pure returns (uint256) {
        return 1;
    }

    function proposeChild(
        uint256 sharedId,
        address proposer,
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        string memory description,
        uint64 startTs,
        uint64 endTs
    ) external onlyRole(META_ROLE) returns (uint256) {
        _details[sharedId] = ProposalDetails({
            proposer: proposer,
            targets: targets,
            values: values,
            calldatas: calldatas,
            start: startTs,
            end: endTs,
            description: description
        });
        _states[sharedId] = IProposalState.Pending;
        return sharedId;
    }

    function setState(uint256 id, IProposalState nextState) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _states[id] = nextState;
    }

    function setTally(uint256 id, uint256 yesVotes, uint256 noVotes, uint256 supply) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _tallies[id] = ProposalTally({yesVotes: yesVotes, noVotes: noVotes, supply: supply});
    }

    function state(uint256 id) external view returns (IProposalState) {
        return _states[id];
    }

    function tally(uint256 id) external view returns (uint256 yesVotes, uint256 noVotes, uint256 supply) {
        ProposalTally storage t = _tallies[id];
        return (t.yesVotes, t.noVotes, t.supply);
    }

    function getProposalDetails(uint256 id)
        external
        view
        returns (
            address proposer,
            address[] memory targets,
            uint256[] memory values,
            bytes[] memory calldatas,
            uint64 start,
            uint64 end,
            string memory description
        )
    {
        ProposalDetails storage d = _details[id];
        return (d.proposer, d.targets, d.values, d.calldatas, d.start, d.end, d.description);
    }
}

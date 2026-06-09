// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.22;

contract MockSnapshotDebtToken {
    struct Entry {
        uint256[] ids;
        mapping(uint256 => uint256) values;
    }

    uint256 private _snapshotId;
    mapping(uint256 => mapping(uint256 => mapping(address => uint256))) private _balances;
    mapping(uint256 => mapping(uint256 => uint256)) private _totalSupply;
    mapping(uint256 => mapping(uint256 => uint256[])) private _supplySnapshotIds;
    mapping(uint256 => mapping(uint256 => mapping(uint256 => uint256))) private _supplyAt;
    mapping(uint256 => mapping(uint256 => mapping(address => Entry))) private _balanceHistory;
    mapping(uint256 => mapping(uint256 => address[])) private _holders;
    mapping(uint256 => mapping(uint256 => mapping(address => bool))) private _holderSeen;

    function mint(address to, uint256 classId, uint256 nonceId, uint256 amount) external {
        _registerHolder(classId, nonceId, to);
        _balances[classId][nonceId][to] += amount;
        _totalSupply[classId][nonceId] += amount;
    }

    function transferPosition(address from, address to, uint256 classId, uint256 nonceId, uint256 amount) external {
        require(_balances[classId][nonceId][from] >= amount, 'INSUFF_BAL');
        _registerHolder(classId, nonceId, to);
        unchecked {
            _balances[classId][nonceId][from] -= amount;
        }
        _balances[classId][nonceId][to] += amount;
    }

    function snapshot() external returns (uint256 id) {
        id = ++_snapshotId;
        _recordAllKnownPositions(id);
    }

    function recordSnapshot(address[] calldata holders, uint256 classId, uint256 nonceId) external returns (uint256 id) {
        id = ++_snapshotId;
        _recordSupply(classId, nonceId, id);
        for (uint256 i = 0; i < holders.length; ++i) {
            _recordHolder(holders[i], classId, nonceId, id);
        }
    }

    function setCurrentSnapshot(uint256 id) external {
        _snapshotId = id;
    }

    function storeSnapshotFor(address holder, uint256 classId, uint256 nonceId, uint256 snapId) external {
        _registerHolder(classId, nonceId, holder);
        _recordSupply(classId, nonceId, snapId);
        _recordHolder(holder, classId, nonceId, snapId);
    }

    function balanceOf(address owner, uint256 classId, uint256 nonceId) external view returns (uint256) {
        return _balances[classId][nonceId][owner];
    }

    function balanceOfAt(address owner, uint256 classId, uint256 nonceId, uint256 snapId) external view returns (uint256) {
        Entry storage entry = _balanceHistory[classId][nonceId][owner];
        uint256 id = _search(entry.ids, snapId);
        return entry.values[id];
    }

    function totalSupplyAt(uint256 classId, uint256 nonceId, uint256 snapId) external view returns (uint256) {
        uint256 id = _search(_supplySnapshotIds[classId][nonceId], snapId);
        return _supplyAt[classId][nonceId][id];
    }

    function burn(address from, uint256 classId, uint256 nonceId, uint256 amount) external {
        require(_balances[classId][nonceId][from] >= amount, 'INSUFF_BAL');
        unchecked {
            _balances[classId][nonceId][from] -= amount;
            _totalSupply[classId][nonceId] -= amount;
        }
    }

    function totalSupply(uint256 classId, uint256 nonceId) external view returns (uint256) {
        return _totalSupply[classId][nonceId];
    }

    function _recordAllKnownPositions(uint256 snapId) private {
        for (uint256 classId = 0; classId < 4; ++classId) {
            for (uint256 nonceId = 0; nonceId < 4; ++nonceId) {
                if (_totalSupply[classId][nonceId] == 0) continue;
                _recordSupply(classId, nonceId, snapId);
                address[] storage holders = _holders[classId][nonceId];
                for (uint256 i = 0; i < holders.length; ++i) {
                    _recordHolder(holders[i], classId, nonceId, snapId);
                }
            }
        }
    }

    function _recordSupply(uint256 classId, uint256 nonceId, uint256 snapId) private {
        uint256[] storage ids = _supplySnapshotIds[classId][nonceId];
        if (ids.length == 0 || ids[ids.length - 1] != snapId) {
            ids.push(snapId);
        }
        _supplyAt[classId][nonceId][snapId] = _totalSupply[classId][nonceId];
    }

    function _recordHolder(address holder, uint256 classId, uint256 nonceId, uint256 snapId) private {
        Entry storage entry = _balanceHistory[classId][nonceId][holder];
        if (entry.ids.length == 0 || entry.ids[entry.ids.length - 1] != snapId) {
            entry.ids.push(snapId);
        }
        entry.values[snapId] = _balances[classId][nonceId][holder];
    }

    function _registerHolder(uint256 classId, uint256 nonceId, address holder) private {
        if (_holderSeen[classId][nonceId][holder]) return;
        _holderSeen[classId][nonceId][holder] = true;
        _holders[classId][nonceId].push(holder);
    }

    function _search(uint256[] storage arr, uint256 snapId) private view returns (uint256) {
        uint256 len = arr.length;
        while (len > 0) {
            uint256 current = arr[len - 1];
            if (current <= snapId) {
                return current;
            }
            unchecked {
                --len;
            }
        }
        return 0;
    }
}

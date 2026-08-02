// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.22;

import "@openzeppelin/contracts/proxy/Clones.sol";

contract MockCloneFactory {
    using Clones for address;

    function deploy(address implementation, bytes calldata initData) external returns (address instance) {
        instance = implementation.clone();
        (bool success, bytes memory result) = instance.call(initData);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }
}

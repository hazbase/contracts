// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/token/ERC721/ERC721Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

interface IERC4907Upgradeable /* is IERC721Upgradeable */ {
    // Logged when the user of an NFT is changed or expires is changed
    event UpdateUser(uint256 indexed tokenId, address indexed user, uint64 expires);

    /// @notice set the user and expires of an NFT
    function setUser(uint256 tokenId, address user, uint64 expires) external;

    /// @notice get the user address of an NFT
    function userOf(uint256 tokenId) external view returns (address);

    /// @notice get the user expires of an NFT
    function userExpires(uint256 tokenId) external view returns (uint64);
}

/// @title ERC4907Upgradeable – ERC-721 rentable extension (double protocol)
abstract contract ERC4907Upgradeable is Initializable, ERC721Upgradeable, IERC4907Upgradeable {
    struct UserInfo { address user; uint64 expires; } // expires = 0 ⇒ none
    mapping(uint256 tokenId => UserInfo) private _users;

    function __ERC4907_init() internal onlyInitializing {}

    // --------------------------------------------------------------------- //
    // IERC4907                                                               //
    // --------------------------------------------------------------------- //
    function setUser(uint256 tokenId, address user, uint64 expires) external virtual override {
        address owner = _ownerOf(tokenId);
        require(_isAuthorized(owner, _msgSender(), tokenId), "ERC4907: not owner nor approved");
        _users[tokenId] = UserInfo({user: user, expires: expires});
        emit UpdateUser(tokenId, user, expires);
    }

    function userOf(uint256 tokenId) public view override returns (address) {
        if (uint256(_users[tokenId].expires) >= block.timestamp) {
            return _users[tokenId].user;
        }
        return address(0);
    }

    function userExpires(uint256 tokenId) external view override returns (uint64) {
        return _users[tokenId].expires;
    }

    // --------------------------------------------------------------------- //
    // Hooks                                                                  //
    // --------------------------------------------------------------------- //
    function _beforeTokenTransfer(address from, address to, uint256 tokenId)
        internal
        virtual
    {
        if (from != to && _users[tokenId].user != address(0)) {
            delete _users[tokenId];            // reset on transfer
            emit UpdateUser(tokenId, address(0), 0);
        }
    }

    function supportsInterface(bytes4 iid)
        public
        view
        virtual
        override
        returns (bool)
    {
        return iid == type(IERC4907Upgradeable).interfaceId || super.supportsInterface(iid);
    }

    uint256[49] private __gap4907;
}

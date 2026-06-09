// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.22;

interface IBondTokenLike {
    function operatorTransferFrom(
        address from,
        address to,
        uint256 classId,
        uint256 nonceId,
        uint256 amount
    ) external;
}

enum OfferStatus { None, Offered, Accepted, Rejected, Cancelled }

struct Offer {
    address issuer;
    address investor;
    address tokenAddress;
    bytes32 partition;
    uint256 tokenId;
    uint256 classId;
    uint256 nonceId;
    uint256 amount;
    bytes32 documentHash;
    string documentURI;
    uint256 expiry;
    uint256 nonce;
    address delegatedTo;
    bytes issuerSig;
    OfferStatus status;
}

contract MockAgreementManager {
    Offer private _offer;
    uint256 public acceptCalls;
    bytes32 public lastAcceptedOfferId;
    bytes public lastInvestorSig;

    function setOffer(Offer calldata offer_) external {
        _offer = Offer({
            issuer: offer_.issuer,
            investor: offer_.investor,
            tokenAddress: offer_.tokenAddress,
            partition: offer_.partition,
            tokenId: offer_.tokenId,
            classId: offer_.classId,
            nonceId: offer_.nonceId,
            amount: offer_.amount,
            documentHash: offer_.documentHash,
            documentURI: offer_.documentURI,
            expiry: offer_.expiry,
            nonce: offer_.nonce,
            delegatedTo: offer_.delegatedTo,
            issuerSig: offer_.issuerSig,
            status: offer_.status
        });
    }

    function getOffer(bytes32) external view returns (Offer memory) {
        return _offer;
    }

    function acceptOffer(bytes32 offerId, bytes calldata investorSig) external {
        acceptCalls += 1;
        lastAcceptedOfferId = offerId;
        lastInvestorSig = investorSig;
        if (_offer.tokenAddress != address(0) && _offer.amount != 0) {
            IBondTokenLike(_offer.tokenAddress).operatorTransferFrom(
                _offer.issuer,
                _offer.investor,
                _offer.classId,
                _offer.nonceId,
                _offer.amount
            );
        }
        _offer.status = OfferStatus.Accepted;
    }
}

// SPDX-License-Identifier: GPL-3.0
/*
    Copyright 2021 0KIMS association.

    This file is generated with [snarkJS](https://github.com/iden3/snarkjs).

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

pragma solidity >=0.7.0 <0.9.0;

contract Groth16Verifier {
    // Scalar field size
    uint256 constant r    = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q   = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax  = 7306002113277226490552699366768181439189549295888031276993324990066367389449;
    uint256 constant alphay  = 12557477388307872381637691987315976605170214804595722707015784020254893174787;
    uint256 constant betax1  = 2255455861455311478164008693641948935613962711323178654612609863088093425468;
    uint256 constant betax2  = 4277132612325823670053689426119547824345710024581610915843642174835223283601;
    uint256 constant betay1  = 16065281617773084994181069160286875113952798839299102742153789290963894492673;
    uint256 constant betay2  = 20770329552742850589354138912572753492049493898686103874854677587523122981762;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 2325234060817041994498446062750098184392436713095022870323560236511089973019;
    uint256 constant deltax2 = 9232893942603710321117350691625265177398233940703642723319668376146888467146;
    uint256 constant deltay1 = 17496788880238895686964525243218622695181509936520823342670386647275074455990;
    uint256 constant deltay2 = 3161869555610314815628922502284507108521241134132975361375060890392752476417;

    
    uint256 constant IC0x = 15906085416801213499605342787224359988160083804734234602735235096708314433929;
    uint256 constant IC0y = 8976566483777427875483420874102635692346206095394328652441162060122118408897;
    
    uint256 constant IC1x = 21564655315726001234694099107800915843562835595299749764040439032555257601654;
    uint256 constant IC1y = 1232315945548331151991957154830592209145747182654739558534017073594540337912;
    
    uint256 constant IC2x = 14711285998320423589619257400064127423423629734772703022498359558194570415054;
    uint256 constant IC2y = 2199832596194224186698070060434031703238211266212827776217210872275913215745;
    
    uint256 constant IC3x = 8178383686520624889712264565664208677753834476552437650104475358468785353458;
    uint256 constant IC3y = 6149307918224355331333377298482729776966568197596685890459273816236284405283;
    
    uint256 constant IC4x = 15439086567947560034152030974485746741916051684557088108497234019029344793788;
    uint256 constant IC4y = 10111209077344184401597171222610767518826383725069965924773549459286005975322;
    
    uint256 constant IC5x = 18454546894710089007457808853067751437502544601939717263189816792897004472868;
    uint256 constant IC5y = 14081635690586457502099529760505625292624574449325330570886248422389432849666;
    
    uint256 constant IC6x = 173911940703017413914404670655010386903790704758551608455883316413666205634;
    uint256 constant IC6y = 9026666294085753230744262988370917014159326190426421483219735624415864086679;
    
    uint256 constant IC7x = 10542477161213363669618800181859543286841604064396525071142800906819514350555;
    uint256 constant IC7y = 16788804503293542714921347310105763852255591077960811665217716486639567261797;
    
    uint256 constant IC8x = 6642930285864674946538712411212908993669938573189539222940859482536685220850;
    uint256 constant IC8y = 19839144600958206497121629872419010812041423102312906749085674004480826794919;
    
    uint256 constant IC9x = 14287859243945286961829427232568315013342225384744186261987340565396298089365;
    uint256 constant IC9y = 2922589879986592739088305604844870339329758069430093481226161566618368459521;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[9] calldata _pubSignals) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, r)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }
            
            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Compute the linear combination vk_x
                
                g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))
                
                g1_mulAccC(_pVk, IC2x, IC2y, calldataload(add(pubSignals, 32)))
                
                g1_mulAccC(_pVk, IC3x, IC3y, calldataload(add(pubSignals, 64)))
                
                g1_mulAccC(_pVk, IC4x, IC4y, calldataload(add(pubSignals, 96)))
                
                g1_mulAccC(_pVk, IC5x, IC5y, calldataload(add(pubSignals, 128)))
                
                g1_mulAccC(_pVk, IC6x, IC6y, calldataload(add(pubSignals, 160)))
                
                g1_mulAccC(_pVk, IC7x, IC7y, calldataload(add(pubSignals, 192)))
                
                g1_mulAccC(_pVk, IC8x, IC8y, calldataload(add(pubSignals, 224)))
                
                g1_mulAccC(_pVk, IC9x, IC9y, calldataload(add(pubSignals, 256)))
                

                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))


                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)


                let success := staticcall(sub(gas(), 2000), 8, _pPairing, 768, _pPairing, 0x20)

                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            // Validate that all evaluations ∈ F
            
            checkField(calldataload(add(_pubSignals, 0)))
            
            checkField(calldataload(add(_pubSignals, 32)))
            
            checkField(calldataload(add(_pubSignals, 64)))
            
            checkField(calldataload(add(_pubSignals, 96)))
            
            checkField(calldataload(add(_pubSignals, 128)))
            
            checkField(calldataload(add(_pubSignals, 160)))
            
            checkField(calldataload(add(_pubSignals, 192)))
            
            checkField(calldataload(add(_pubSignals, 224)))
            
            checkField(calldataload(add(_pubSignals, 256)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }

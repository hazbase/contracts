pragma circom 2.1.8;

include "poseidon.circom";
include "mux1.circom";
include "bitify.circom";

/**************************************************
 * MerkleProof — fixed-depth Merkle inclusion check
 **************************************************/
template MerkleProof(n) {
    signal input root;
    signal input leaf;
    signal input siblings[n];
    signal input indices[n];

    component hashers[n];
    signal cur[n + 1];
    cur[0] <== leaf;

    component muxL[n];
    component muxR[n];

    for (var i = 0; i < n; i++) {
        muxL[i] = Mux1();
        muxL[i].c[0] <== cur[i];
        muxL[i].c[1] <== siblings[i];
        muxL[i].s    <== indices[i];

        muxR[i] = Mux1();
        muxR[i].c[0] <== siblings[i];
        muxR[i].c[1] <== cur[i];
        muxR[i].s    <== indices[i];

        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== muxL[i].out;
        hashers[i].inputs[1] <== muxR[i].out;

        cur[i + 1] <== hashers[i].out;
    }

    cur[n] === root;
}

/**************************************************
 * AllowlistCredential — dual-root membership proof (ZKEx/ALLOWLIST)
 *
 * Public inputs layout (recommended legacy-compatible):
 *   [0] issuerRoot
 *   [1] allowRoot
 *   [2] nullifier
 *   [3] addr
 *   [4] statementHash
 *   [5] leaf (commitment) = Poseidon(value, salt)
 *
 * Issuer tree leaf:
 *   issuerLeaf = Poseidon(leaf, addr, domain)
 * Allow tree leaf:
 *   allowLeaf  = Poseidon(value)
 **************************************************/
template AllowlistCredential(depthIssuer, depthAllow) {
    /*──────────── public inputs ────────────*/
    signal input issuerRoot;
    signal input allowRoot;
    signal input nullifier;
    signal input addr;
    signal input statementHash;
    signal input leaf;              // commitment: Poseidon(value, salt)

    /*──────────── private inputs ───────────*/
    signal input policyId;
    signal input policyVersion;
    signal input domain;
    signal input value;
    signal input salt;
    signal input idNull;
    signal input pathIssuer[depthIssuer];
    signal input posIssuer[depthIssuer];
    signal input pathAllow[depthAllow];
    signal input posAllow[depthAllow];

    // Enforce addr is within uint160 to match address(uint160(...)) on-chain.
    component addrBits = Num2Bits(160);
    addrBits.in <== addr;

    // Bind leaf = Poseidon(value, salt)
    component leafUserCmt = Poseidon(2);
    leafUserCmt.inputs[0] <== value;
    leafUserCmt.inputs[1] <== salt;
    leafUserCmt.out === leaf;

    // Issuer leaf: Poseidon(leaf, addr, domain)
    component issuerLeaf = Poseidon(3);
    issuerLeaf.inputs[0] <== leaf;
    issuerLeaf.inputs[1] <== addr;
    issuerLeaf.inputs[2] <== domain;

    // Prove inclusion in issuerRoot
    component incIssuer = MerkleProof(depthIssuer);
    incIssuer.root <== issuerRoot;
    incIssuer.leaf <== issuerLeaf.out;
    for (var i = 0; i < depthIssuer; i++) {
        incIssuer.siblings[i] <== pathIssuer[i];
        incIssuer.indices[i]  <== posIssuer[i];
    }

    // Allowlist leaf: Poseidon(value)
    component allowLeaf = Poseidon(1);
    allowLeaf.inputs[0] <== value;

    // Prove inclusion in allowRoot
    component incAllow = MerkleProof(depthAllow);
    incAllow.root <== allowRoot;
    incAllow.leaf <== allowLeaf.out;
    for (var j = 0; j < depthAllow; j++) {
        incAllow.siblings[j] <== pathAllow[j];
        incAllow.indices[j]  <== posAllow[j];
    }

    // statementHash binding:
    // s1 = Poseidon(policyId, policyVersion)
    // s2 = Poseidon(allowRoot, addr)
    // s3 = Poseidon(s1, s2, domain)
    component s1 = Poseidon(2);
    s1.inputs[0] <== policyId;
    s1.inputs[1] <== policyVersion;

    component s2 = Poseidon(2);
    s2.inputs[0] <== allowRoot;
    s2.inputs[1] <== addr;

    component s3 = Poseidon(3);
    s3.inputs[0] <== s1.out;
    s3.inputs[1] <== s2.out;
    s3.inputs[2] <== domain;

    s3.out === statementHash;

    // nullifier binding:
    // n1 = Poseidon(idNull, policyId)
    // n2 = Poseidon(n1, policyVersion)
    component n1 = Poseidon(2);
    n1.inputs[0] <== idNull;
    n1.inputs[1] <== policyId;

    component n2 = Poseidon(2);
    n2.inputs[0] <== n1.out;
    n2.inputs[1] <== policyVersion;

    n2.out === nullifier;
}

component main {public [
    issuerRoot,
    allowRoot,
    nullifier,
    addr,
    statementHash,
    leaf
]} = AllowlistCredential(20, 16);

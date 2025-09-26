pragma circom 2.1.8;

include "poseidon.circom";
include "mux1.circom";
include "bitify.circom";

/**************************************************
 * MerkleProof — fixed-depth Merkle inclusion check
 *  - `indices` are boolean (0: left, 1: right)
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
        // choose left/right ordering depending on indices[i]
        muxL[i] = Mux1();
        muxL[i].c[0] <== cur[i];        // index = 0 => leaf on left
        muxL[i].c[1] <== siblings[i];   // index = 1 => sibling on left
        muxL[i].s    <== indices[i];

        muxR[i] = Mux1();
        muxR[i].c[0] <== siblings[i];   // mirror
        muxR[i].c[1] <== cur[i];
        muxR[i].s    <== indices[i];

        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== muxL[i].out;
        hashers[i].inputs[1] <== muxR[i].out;

        cur[i + 1] <== hashers[i].out;
    }

    // final calculated root must match the provided root
    cur[n] === root;
}

/**************************************************
 * AllowlistCredential — dual-root membership proof
 *
 * Proves that:
 *   (A) value is committed by issuer and bound to (addr, domain)
 *       inside issuerRoot; AND
 *   (B) the same value is a member of policy allowRoot.
 *
 * Also binds the statement to (policyId, policyVersion, allowRoot, addr, domain)
 * and exposes a policy-bound nullifier Poseidon(idNull, policyId, policyVersion).
 *
 * Notes:
 *  - "value" can be a country code (e.g., ISO-3166 numeric) or any scalar attribute.
 *  - No non-quadratic constraints introduced.
 **************************************************/
template AllowlistCredential(depthIssuer, depthAllow) {
    /*──────────── public inputs ────────────*/
    signal input issuerRoot;        // issuer's Merkle root (SoT for user's attribute)
    signal input allowRoot;         // policy allowlist Merkle root
    signal input nullifier;         // expected nullifier (policy-bound)
    signal input addr;              // wallet address coerced to field
    signal input statementHash;     // expected Poseidon-based binding
    signal input leaf;              // KYC hash (Poseidon of KYC data + salt)

    /*──────────── private inputs ───────────*/
    signal input policyId;          // arbitrary field element (e.g., keccak256(...) mod p)
    signal input policyVersion;     // monotonic version (freshness)
    signal input domain;            // domain separator (e.g., chain/app)
    signal input value;             // attribute value (e.g., 392 for JP)
    signal input salt;              // per-user salt for privacy
    signal input idNull;            // user-secret for nullifier uniqueness
    signal input pathIssuer[depthIssuer];
    signal input posIssuer[depthIssuer]; // 0/1
    signal input pathAllow[depthAllow];
    signal input posAllow[depthAllow];   // 0/1

    /* (optional) lightweight range check for value if you expect small domain, e.g., < 2^16 */
    // Comment-out if not needed.
    // component vBits = Num2Bits(16);
    // vBits.in <== value;

    /* issuer commitment: Poseidon(value, salt) */
    component leafUserCmt = Poseidon(2);
    leafUserCmt.inputs[0] <== value;
    leafUserCmt.inputs[1] <== salt;

    component pick = Mux1();
    pick.c[0] <== leaf;   // KYC
    pick.c[1] <== leafUserCmt.out;// Score
    pick.s    <== 1;
    signal commitLeaf <== pick.out;

    commitLeaf === leaf;

    /* bind commitment to address + domain to make it user/context-specific */
    component issuerLeaf = Poseidon(3);
    issuerLeaf.inputs[0] <== leafUserCmt.out;
    issuerLeaf.inputs[1] <== addr;
    issuerLeaf.inputs[2] <== domain;

    /* Prove inclusion in issuerRoot */
    component incIssuer = MerkleProof(depthIssuer);
    incIssuer.root   <== issuerRoot;
    incIssuer.leaf   <== issuerLeaf.out;
    for (var i = 0; i < depthIssuer; i++) {
        incIssuer.siblings[i] <== pathIssuer[i];
        incIssuer.indices[i]  <== posIssuer[i];
    }

    /* allowlist membership for the SAME value */
    component allowLeaf = Poseidon(1);
    allowLeaf.inputs[0] <== value;

    component incAllow = MerkleProof(depthAllow);
    incAllow.root   <== allowRoot;
    incAllow.leaf   <== allowLeaf.out;
    for (var j = 0; j < depthAllow; j++) {
        incAllow.siblings[j] <== pathAllow[j];
        incAllow.indices[j]  <== posAllow[j];
    }

    /* bind statement:
         statementHash == Poseidon(policyId, policyVersion, allowRoot, addr, domain)
       Use arity-3 chaining with available Poseidon components.
       s1 = Poseidon(policyId, policyVersion)
       s2 = Poseidon(allowRoot, addr)
       s3 = Poseidon(s1, s2, domain)
    */
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

    /* compute and expose a policy-bound nullifier:
         nullifier == Poseidon(idNull, policyId, policyVersion)
       via chaining:
         n1 = Poseidon(idNull, policyId)
         n2 = Poseidon(n1, policyVersion)
    */
    component n1 = Poseidon(2);
    n1.inputs[0] <== idNull;
    n1.inputs[1] <== policyId;

    component n2 = Poseidon(2);
    n2.inputs[0] <== n1.out;
    n2.inputs[1] <== policyVersion;

    n2.out === nullifier;
}

/* -------- Main component (adjust depths to your trees) --------
   - public signal order must match your verifier's expectation.
*/
component main {public [
    issuerRoot,
    allowRoot,
    nullifier,
    addr,
    statementHash,
    leaf
]} = AllowlistCredential(20, 16);

pragma circom 2.1.8;

include "poseidon.circom";
include "mux1.circom";
include "bitify.circom";

template GEQ32() {
    signal input  a;           // 0 .. 2^32-1
    signal input  b;           // 0 .. 2^32-1
    signal output out;         // 1 iff a >= b

    signal diff;
    diff <== a + (1 << 33) - b;        // 0 .. 2^33 + 2^32 - 2

    component bits = Num2Bits(34);
    bits.in <== diff;

    out <== bits.out[33];
}

/**************************************************
 * MerkleProof — fixed-depth Merkle inclusion check
 *  - `indices` are boolean (0: left, 1: right)
 *************************************************/
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
 * BaselineCredential — EIP-8036 baseline-style proof
 *
 * Public inputs layout (must match on-chain expectation):
 *   [0] mode      : relation bitmask (GT=1, LT=2, EQ=4), 0 means KYC-only
 *   [1] root      : Merkle root / anchor (must equal on-chain leafFull)
 *   [2] nullifier : Poseidon(idNull, root)
 *   [3] addr      : uint160 address as field element
 *   [4] threshold : uint32 (constrained)
 *   [5] leaf      : commitment:
 *                  - if mode==0: arbitrary (e.g., KYC hash commitment)
 *                  - if mode!=0: leaf MUST equal Poseidon(score, rand)
 *
 * Merkle tree leaf used for inclusion:
 *   treeLeaf = Poseidon(leaf, addr, domain)
 *************************************************/
template BaselineCredential(depth) {
    /*──────────── public inputs ────────────*/
    signal input mode;
    signal input root;
    signal input nullifier;
    signal input addr;
    signal input threshold;
    signal input leaf;

    /*──────────── private inputs ───────────*/
    signal input domain;
    signal input idNull;
    signal input path[depth];
    signal input pathPos[depth];

    signal input score;
    signal input rand;

    // Enforce addr is within uint160 to match address(uint160(...)) on-chain.
    component addrBits = Num2Bits(160);
    addrBits.in <== addr;

    // Enforce score/threshold are uint32 for GEQ32 correctness.
    component scoreBits = Num2Bits(32);
    scoreBits.in <== score;

    component thBits = Num2Bits(32);
    thBits.in <== threshold;

    // Determine if mode == 0 (KYC-only).
    component is0 = IsZero();
    is0.in <== mode; // is0.out is boolean

    // Score commitment: Poseidon(score, rand)
    component cmt = Poseidon(2);
    cmt.inputs[0] <== score;
    cmt.inputs[1] <== rand;

    // If mode != 0, bind leaf to score commitment:
    // (1 - is0) * (leaf - cmt) == 0
    signal not0 <== 1 - is0.out;
    not0 * (leaf - cmt.out) === 0;

    /* 1) Bind leaf ↔ addr ↔ domain into the tree leaf */
    component h = Poseidon(3);
    h.inputs[0] <== leaf;
    h.inputs[1] <== addr;
    h.inputs[2] <== domain;
    signal treeLeaf <== h.out;

    /* 2) Prove inclusion */
    component inc = MerkleProof(depth);
    inc.root <== root;
    inc.leaf <== treeLeaf;
    for (var i = 0; i < depth; i++) {
        inc.siblings[i] <== path[i];
        inc.indices[i]  <== pathPos[i];
    }

    /* 3) Comparison (only required when mode != 0) */
    // Base comparisons
    component ge = GEQ32();  // score >= threshold
    ge.a <== score;
    ge.b <== threshold;

    component le = GEQ32();  // threshold >= score  => score <= threshold
    le.a <== threshold;
    le.b <== score;

    component eqz = IsZero();
    eqz.in <== score - threshold;

    signal isEq <== eqz.out;
    signal gt  <== ge.out * (1 - isEq);
    signal lt  <== le.out * (1 - isEq);

    // Decode mode bits (GT=1, LT=2, EQ=4)
    component mb = Num2Bits(8);
    mb.in <== mode;

    signal bitGT <== mb.out[0];
    signal bitLT <== mb.out[1];
    signal bitEQ <== mb.out[2];

    // Enforce higher bits are zero.
    mb.out[3] === 0;
    mb.out[4] === 0;
    mb.out[5] === 0;
    mb.out[6] === 0;
    mb.out[7] === 0;

    // Selected relations
    signal selGT <== bitGT * gt;
    signal selLT <== bitLT * lt;
    signal selEQ <== bitEQ * isEq;

    // OR combine (boolean OR via a + b - a*b)
    signal anySel1 <== selGT + selLT - selGT * selLT;
    signal anySel  <== anySel1 + selEQ - anySel1 * selEQ;

    // Final condition:
    // - if mode==0 => pass
    // - else => at least one selected relation must hold
    signal cond <== is0.out + anySel;
    cond === 1;

    /* 4) Nullifier */
    component nh = Poseidon(2);
    nh.inputs[0] <== idNull;
    nh.inputs[1] <== root;
    nh.out === nullifier;
}

// depth = 20 (2^20 leaves ≈ 1M entries)
component main {public [
    mode,
    root,
    nullifier,
    addr,
    threshold,
    leaf
]} = BaselineCredential(20);

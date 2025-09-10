pragma circom 2.1.8;

include "poseidon.circom";
include "mux1.circom";
include "bitify.circom";

template GEQ32() {
    signal input  a;           // 0 … 2^32-1
    signal input  b;
    signal output out;         // 1 ⇔ a ≥ b

    signal diff;
    diff <== a + (1 << 33) - b;        // 0 … 2^33 + 2^32 − 2

    component bits = Num2Bits(34);
    bits.in <== diff;

    out <== bits.out[33];
}

/**************************************************
 * MerkleProof — fixed‑depth Merkle inclusion check
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
        // choose left/right ordering depending on `indices[i]`
        muxL[i] = Mux1();
        muxL[i].c[0] <== cur[i];        // when index = 0 => leaf on left
        muxL[i].c[1] <== siblings[i];   // when index = 1 => sibling on left
        muxL[i].s    <== indices[i];

        muxR[i] = Mux1();
        muxR[i].c[0] <== siblings[i];   // mirror of the above
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
 * UnifiedCredential — verify that
 *   Poseidon(leaf, addr) is contained in a Merkle tree `root`,
 *   and expose a user‑unique `nullifier = Poseidon(idNull, root)`
 *************************************************/
template UnifiedCredential(depth) {
    /*──────────── public inputs ────────────*/
    signal input mode;
    signal input root;       // current Merkle root
    signal input nullifier;  // expected nullifier hash
    signal input addr;       // wallet address (uint)
    signal input threshold;
    signal input leaf;       // KYC hash (Poseidon of KYC data + salt)
    
    /*──────────── private inputs ───────────*/
    signal input idNull;             // user‑secret for nullifier uniqueness
    signal input path[depth];        // Merkle siblings
    signal input pathPos[depth]; // 0 = left, 1 = right

    signal input score;
    signal input rand;

    component cmt = Poseidon(2);
    cmt.inputs[0] <== score;
    cmt.inputs[1] <== rand;

    component nz = GEQ32();   // GEQ32( mode , 1 ) → mode>=1
    nz.a <== mode;
    nz.b <== 1;

    signal isScore <== nz.out;

    component pick = Mux1();
    pick.c[0] <== leaf;   // KYC
    pick.c[1] <== cmt.out;// Score
    pick.s    <== isScore;
    signal commitLeaf <== pick.out;

    commitLeaf === leaf;

    /* 1. bind leaf ↔ addr */
    component h = Poseidon(2);
    h.inputs[0] <== commitLeaf;
    h.inputs[1] <== addr;
    signal hashOut <== h.out;

    /* 2. prove inclusion */
    component inc = MerkleProof(depth);
    inc.root <== root;
    inc.leaf <== hashOut;
    for (var i = 0; i < depth; i++) {
        inc.siblings[i] <== path[i];
        inc.indices[i]  <== pathPos[i];
    }

    component ge = GEQ32();   // a ≥ b
    component le = GEQ32();   // b ≥ a  ⇒ a ≤ b
    ge.a <== score;    ge.b <== threshold;
    le.a <== threshold; le.b <== score;

    signal isEq <== ge.out * le.out;

    component is0 = IsZero();  is0.in <== mode;           // mode == 0
    component is1 = IsZero();  is1.in <== mode - 1;
    component is2 = IsZero();  is2.in <== mode - 2;
    component is3 = IsZero();  is3.in <== mode - 3;

    signal cond1 <== is1.out * ge.out;     // ≥
    signal cond2 <== is2.out * le.out;     // ≤
    signal cond3 <== is3.out * isEq;       // =
    signal cond  <== cond1 + cond2 + cond3 + is0.out;
    cond === 1;

    /* 3. compute & expose nullifier */
    component nh = Poseidon(2);
    nh.inputs[0] <== idNull;
    nh.inputs[1] <== root;
    nh.out === nullifier;
}

// depth = 20 (2^20 leaves ≈ 1M entries)
component main {public [mode, root, nullifier, addr, threshold, leaf]} = UnifiedCredential(20);

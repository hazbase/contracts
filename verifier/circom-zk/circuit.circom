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
    signal input domain;    // private input (domain separator)
    
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
    component h = Poseidon(3);
    h.inputs[0] <== commitLeaf;
    h.inputs[1] <== addr;
    h.inputs[2] <== domain;
    signal hashOut <== h.out;

    /* 2. prove inclusion */
    component inc = MerkleProof(depth);
    inc.root <== root;
    inc.leaf <== hashOut;
    for (var i = 0; i < depth; i++) {
        inc.siblings[i] <== path[i];
        inc.indices[i]  <== pathPos[i];
    }

    // ---- Base comparisons ----
    component ge = GEQ32();            // a ≥ b
    ge.a <== score;
    ge.b <== threshold;

    component le = GEQ32();            // b ≥ a  ⇒ a ≤ b
    le.a <== threshold;
    le.b <== score;

    component eqz = IsZero();          // equality test
    eqz.in <== score - threshold;

    signal isEq <== eqz.out;           // 1 ⇔ score == threshold
    signal gt  <== ge.out * (1 - isEq);// 1 ⇔ score >  threshold
    signal lt  <== le.out * (1 - isEq);// 1 ⇔ score <  threshold

    // ---- Decode `mode` as bit flags (GT=1, LT=2, EQ=4) ----
    component mb = Num2Bits(8);
    mb.in <== mode;

    signal bitGT <== mb.out[0];        // bit 0
    signal bitLT <== mb.out[1];        // bit 1
    signal bitEQ <== mb.out[2];        // bit 2

    // Safety: enforce higher bits to be zero (reject unexpected flags)
    mb.out[3] === 0;
    mb.out[4] === 0;
    mb.out[5] === 0;
    mb.out[6] === 0;
    mb.out[7] === 0;

    // ---- Satisfy if ANY selected relation holds (logical OR) ----
    signal selGT <== bitGT * gt;       // GT selected AND true
    signal selLT <== bitLT * lt;       // LT selected AND true
    signal selEQ <== bitEQ * isEq;     // EQ selected AND true

    // anySel1 = selGT OR selLT
    signal anySel1 <== selGT + selLT - selGT * selLT;

    // anySel  = anySel1 OR selEQ
    signal anySel  <== anySel1 + selEQ - anySel1 * selEQ;

    // Optional: mode==0 means unconditional pass (keep if you want legacy behavior)
    component is0 = IsZero();
    is0.in <== mode;

    // Final constraint: pass if (mode==0) OR (any selected relation holds)
    signal cond <== is0.out + anySel;
    cond === 1;

    /* 3. compute & expose nullifier */
    component nh = Poseidon(2);
    nh.inputs[0] <== idNull;
    nh.inputs[1] <== root;
    nh.out === nullifier;
}

// depth = 20 (2^20 leaves ≈ 1M entries)
component main {public [mode, root, nullifier, addr, threshold, leaf]} = UnifiedCredential(20);

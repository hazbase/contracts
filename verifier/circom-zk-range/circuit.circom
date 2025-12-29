pragma circom 2.1.8;

include "poseidon.circom";
include "mux1.circom";
include "bitify.circom";

template GEQ32() {
    signal input  a;           // 0 .. 2^32-1
    signal input  b;           // 0 .. 2^32-1
    signal output out;         // 1 iff a >= b

    signal diff;
    diff <== a + (1 << 33) - b;

    component bits = Num2Bits(34);
    bits.in <== diff;

    out <== bits.out[33];
}

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
 * RangeCredential — ZKEx/RANGE profile (uint32 value)
 *
 * Public inputs (len=8):
 *   [0] root, [1] nullifier, [2] leaf, [3] addr, [4] lower, [5] upper, [6] statementHash, [7] reserved(0)
 *
 * Leaf construction (domain separated):
 *   treeLeaf := Poseidon(leaf, addr, domain)
 **************************************************/
template RangeCredential(depth) {
    /* public */
    signal input root;
    signal input nullifier;
    signal input leaf;
    signal input addr;
    signal input lower;
    signal input upper;
    signal input statementHash;
    signal input reserved;

    /* private */
    signal input domain;
    signal input idNull;
    signal input value;
    signal input salt;
    signal input path[depth];
    signal input pathPos[depth];

    // Enforce reserved == 0 (stabilize profile / prevent junk)
    reserved === 0;

    // Enforce addr is uint160 (matches address(uint160(..)) on-chain)
    component addrBits = Num2Bits(160);
    addrBits.in <== addr;

    // Enforce 32-bit domain for comparisons
    component vBits = Num2Bits(32); vBits.in <== value;
    component lBits = Num2Bits(32); lBits.in <== lower;
    component uBits = Num2Bits(32); uBits.in <== upper;

    // Bind leaf = Poseidon(value, salt)
    component cmt = Poseidon(2);
    cmt.inputs[0] <== value;
    cmt.inputs[1] <== salt;
    cmt.out === leaf;

    // Range check: value >= lower AND upper >= value
    component ge1 = GEQ32(); ge1.a <== value; ge1.b <== lower;
    component ge2 = GEQ32(); ge2.a <== upper; ge2.b <== value;
    (ge1.out * ge2.out) === 1;

    // Merkle inclusion: Poseidon(leaf, addr, domain) ∈ root
    component treeLeaf = Poseidon(3);
    treeLeaf.inputs[0] <== leaf;
    treeLeaf.inputs[1] <== addr;
    treeLeaf.inputs[2] <== domain;

    component inc = MerkleProof(depth);
    inc.root <== root;
    inc.leaf <== treeLeaf.out;
    for (var i = 0; i < depth; i++) {
        inc.siblings[i] <== path[i];
        inc.indices[i]  <== pathPos[i];
    }

    // Nullifier: Poseidon(idNull, root)
    component nh = Poseidon(2);
    nh.inputs[0] <== idNull;
    nh.inputs[1] <== root;
    nh.out === nullifier;

    // Statement binding (optional but recommended):
    // statementHash := Poseidon( Poseidon(root, addr), Poseidon(lower, upper), domain )
    component s1 = Poseidon(2);
    s1.inputs[0] <== root;
    s1.inputs[1] <== addr;

    component s2 = Poseidon(2);
    s2.inputs[0] <== lower;
    s2.inputs[1] <== upper;

    component s3 = Poseidon(3);
    s3.inputs[0] <== s1.out;
    s3.inputs[1] <== s2.out;
    s3.inputs[2] <== domain;

    s3.out === statementHash;
}

component main {public [
    root,
    nullifier,
    leaf,
    addr,
    lower,
    upper,
    statementHash,
    reserved
]} = RangeCredential(20);

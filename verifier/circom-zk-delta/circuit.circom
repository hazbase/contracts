pragma circom 2.1.8;

include "poseidon.circom";
include "mux1.circom";
include "bitify.circom";

template GEQ32() {
    signal input  a;
    signal input  b;
    signal output out;

    signal diff;
    diff <== a + (1 << 33) - b;

    component bits = Num2Bits(34);
    bits.in <== diff;

    out <== bits.out[33];
}

template GEQ34() {
    signal input a;   // 0 .. 2^34-1
    signal input b;
    signal output out; // 1 iff a >= b

    signal diff;
    diff <== a + (1 << 35) - b;

    component bits = Num2Bits(36);
    bits.in <== diff;

    out <== bits.out[35];
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
 * DeltaCredential — ZKEx/DELTA profile (uint32 values)
 *
 * Public inputs (len=9):
 *   [0] root, [1] epoch, [2] nullifier, [3] addr, [4] delta, [5] leaf, [6] statementHash, [7] r0, [8] r1
 *
 * Leaf binds two epoch-adjacent values (cur/prev) so proof only needs current root:
 *   leaf := Poseidon(valueCur, valuePrev, salt)
 *
 * Delta constraint:
 *   abs(valueCur - valuePrev) <= delta
 **************************************************/
template DeltaCredential(depth) {
    /* public */
    signal input root;
    signal input epoch;
    signal input nullifier;
    signal input addr;
    signal input delta;
    signal input leaf;
    signal input statementHash;
    signal input reserved0;
    signal input reserved1;

    /* private */
    signal input domain;
    signal input idNull;
    signal input valueCur;
    signal input valuePrev;
    signal input salt;
    signal input path[depth];
    signal input pathPos[depth];

    reserved0 === 0;
    reserved1 === 0;

    // Enforce addr is uint160
    component addrBits = Num2Bits(160);
    addrBits.in <== addr;

    // Enforce 32-bit range for arithmetic
    component cBits = Num2Bits(32); cBits.in <== valueCur;
    component pBits = Num2Bits(32); pBits.in <== valuePrev;
    component dBits = Num2Bits(32); dBits.in <== delta;

    // Bind leaf = Poseidon(valueCur, valuePrev, salt)
    component cmt = Poseidon(3);
    cmt.inputs[0] <== valueCur;
    cmt.inputs[1] <== valuePrev;
    cmt.inputs[2] <== salt;
    cmt.out === leaf;

    // Merkle inclusion: treeLeaf = Poseidon(leaf, addr, domain)
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

    // Enforce |valueCur - valuePrev| <= delta using two inequalities:
    // 1) valueCur <= valuePrev + delta
    // 2) valuePrev <= valueCur + delta
    // All values are constrained to uint32, so additions fit in < 2^33.

    signal sumPrev <== valuePrev + delta;
    signal sumCur  <== valueCur + delta;

    // valueCur <= sumPrev  <=>  sumPrev >= valueCur
    component le1 = GEQ34();
    le1.a <== sumPrev;
    le1.b <== valueCur;
    le1.out === 1;

    // valuePrev <= sumCur   <=>  sumCur >= valuePrev
    component le2 = GEQ34();
    le2.a <== sumCur;
    le2.b <== valuePrev;
    le2.out === 1;

    // Epoch-bound nullifier (prevents cross-epoch reuse when contract enforces epoch equality):
    // nullifier := Poseidon( Poseidon(idNull, epoch), root )
    component n1 = Poseidon(2);
    n1.inputs[0] <== idNull;
    n1.inputs[1] <== epoch;

    component n2 = Poseidon(2);
    n2.inputs[0] <== n1.out;
    n2.inputs[1] <== root;

    n2.out === nullifier;

    // Statement binding (optional but recommended):
    // statementHash := Poseidon( Poseidon(root, addr), Poseidon(delta, epoch), domain )
    component s1 = Poseidon(2);
    s1.inputs[0] <== root;
    s1.inputs[1] <== addr;

    component s2 = Poseidon(2);
    s2.inputs[0] <== delta;
    s2.inputs[1] <== epoch;

    component s3 = Poseidon(3);
    s3.inputs[0] <== s1.out;
    s3.inputs[1] <== s2.out;
    s3.inputs[2] <== domain;

    s3.out === statementHash;
}

component main {public [
    root,
    epoch,
    nullifier,
    addr,
    delta,
    leaf,
    statementHash,
    reserved0,
    reserved1
]} = DeltaCredential(20);

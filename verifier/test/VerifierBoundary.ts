import { expect } from 'chai';
import { ethers } from 'hardhat';

// The zk package already bundles the proof generators and assets we use internally.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { genValuesWithAnchor, generateProof, generateProofAllowlist } = require('../../../@hazbase/zk/dist/index.js');

const SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

type Groth16Proof = {
  a: readonly [string, string];
  b: readonly [[string, string], [string, string]];
  c: readonly [string, string];
};

type PlainBundle = {
  proof: Groth16Proof;
  publicSignals: readonly [bigint, bigint, bigint, bigint, bigint, bigint];
};

function mutateProofA(proof: Groth16Proof): [bigint, bigint] {
  return [BigInt(proof.a[0]) + 1n, BigInt(proof.a[1])];
}

describe('Verifier boundary coverage', function () {
  this.timeout(120_000);

  let verifier: Awaited<ReturnType<typeof ethers.deployContract>>;
  let verifierGroup: Awaited<ReturnType<typeof ethers.deployContract>>;
  let plainBundle: PlainBundle;
  let groupBundle: PlainBundle;
  let holderAddress: string;
  let chainId: number;

  before(async function () {
    const [holder] = await ethers.getSigners();
    holderAddress = holder.address;
    chainId = Number((await ethers.provider.getNetwork()).chainId);

    verifier = await ethers.deployContract('Verifier');
    verifierGroup = await ethers.deployContract('VerifierGroup');
    await verifier.waitForDeployment();
    await verifierGroup.waitForDeployment();

    const anchor = await genValuesWithAnchor({
      score: 392n,
      walletAddress: holderAddress,
      chainId,
      mtcAddress: await verifier.getAddress(),
      rand: 19n,
      nextIndex: 0,
    });

    plainBundle = await generateProof(
      {
        govId: 'JP-TEST-1',
        name: 'Alice Verifier',
        dobYMD: 19900101,
        country: 392,
      },
      holderAddress,
      {
        mode: 'EQ',
        threshold: 392n,
        score: 392n,
        idNull: 77n,
        rand: 19n,
        merklePath: anchor.merklePath,
        chainId,
        mtcAddress: await verifier.getAddress(),
      }
    );

    groupBundle = await generateProofAllowlist({
      list: [391, 392, 410, 840, 124, 999],
      policyId: ethers.id('verifier-group-policy'),
      policyVersion: 1,
      addr: holderAddress,
      value: 392,
      salt: 55n,
      idNull: 88n,
      chainId,
      mtcAddress: await verifierGroup.getAddress(),
    });
  });

  it('accepts a valid Groth16 proof for the plain verifier', async function () {
    expect(
      await verifier.verifyProof(
        plainBundle.proof.a,
        plainBundle.proof.b,
        plainBundle.proof.c,
        plainBundle.publicSignals
      )
    ).to.equal(true);
  });

  it('rejects zeroed proof inputs for the plain verifier', async function () {
    expect(
      await verifier.verifyProof(
        [0n, 0n],
        [[0n, 0n], [0n, 0n]],
        [0n, 0n],
        [0n, 0n, 0n, 0n, 0n, 0n]
      )
    ).to.equal(false);
  });

  it('rejects out-of-field public signals for the plain verifier', async function () {
    const badSignals = [...plainBundle.publicSignals] as bigint[];
    badSignals[0] = SCALAR_FIELD;

    expect(
      await verifier.verifyProof(
        plainBundle.proof.a,
        plainBundle.proof.b,
        plainBundle.proof.c,
        badSignals as [bigint, bigint, bigint, bigint, bigint, bigint]
      )
    ).to.equal(false);
  });

  it('rejects mutated proof coordinates for the plain verifier', async function () {
    expect(
      await verifier.verifyProof(
        mutateProofA(plainBundle.proof),
        plainBundle.proof.b,
        plainBundle.proof.c,
        plainBundle.publicSignals
      )
    ).to.equal(false);
  });

  it('accepts a valid Groth16 proof for the group verifier', async function () {
    expect(
      await verifierGroup.verifyProof(
        groupBundle.proof.a,
        groupBundle.proof.b,
        groupBundle.proof.c,
        groupBundle.publicSignals
      )
    ).to.equal(true);
  });

  it('rejects zeroed proof inputs for the group verifier', async function () {
    expect(
      await verifierGroup.verifyProof(
        [0n, 0n],
        [[0n, 0n], [0n, 0n]],
        [0n, 0n],
        [0n, 0n, 0n, 0n, 0n, 0n]
      )
    ).to.equal(false);
  });

  it('rejects out-of-field public signals for the group verifier', async function () {
    const badSignals = [...groupBundle.publicSignals] as bigint[];
    badSignals[1] = SCALAR_FIELD;

    expect(
      await verifierGroup.verifyProof(
        groupBundle.proof.a,
        groupBundle.proof.b,
        groupBundle.proof.c,
        badSignals as [bigint, bigint, bigint, bigint, bigint, bigint]
      )
    ).to.equal(false);
  });

  it('rejects mutated proof coordinates for the group verifier', async function () {
    expect(
      await verifierGroup.verifyProof(
        mutateProofA(groupBundle.proof),
        groupBundle.proof.b,
        groupBundle.proof.c,
        groupBundle.publicSignals
      )
    ).to.equal(false);
  });
});

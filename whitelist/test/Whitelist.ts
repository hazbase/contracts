import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';

function emitEquityLedger(entry: Record<string, unknown>) {
  if (process.env.RWA_EQUITY_LEDGER_OUTPUT === '1') {
    console.log(`RWA_EQUITY_LEDGER::${JSON.stringify(entry)}`);
  }
}

async function deployWhitelistFixture(options?: { initialRoot?: string; verifierAddress?: string }) {
  const [admin, basicUser, zkUser, outsider] = await ethers.getSigners();
  const verifier = await ethers.deployContract('MockVerifier');
  const factory = await ethers.getContractFactory('Whitelist');
  const root = options?.initialRoot ?? ethers.keccak256(ethers.toUtf8Bytes('warehouse-stock-root-2026-03-19'));
  const whitelist = await upgrades.deployProxy(
    factory,
    [admin.address, root, options?.verifierAddress ?? (await verifier.getAddress()), []],
    {
      kind: 'uups',
      initializer: 'initialize',
      unsafeAllow: ['constructor'],
    }
  );
  await whitelist.waitForDeployment();
  return { admin, basicUser, zkUser, outsider, verifier, whitelist, root };
}

describe('Whitelist internal common-stock coverage', function () {
  it('enforces batch updates, pause guards, and ZK downgrade protection', async function () {
    const { basicUser, zkUser, whitelist, root } = await deployWhitelistFixture();

    await whitelist.addBatch([basicUser.address]);
    expect(await whitelist.isWhitelisted(basicUser.address)).to.equal(true);

    const pubSignals = [0n, BigInt(root), 11n, BigInt(zkUser.address), 0n, 0n] as const;
    await whitelist.addWithVerify(zkUser.address, [0n, 0n], [[0n, 0n], [0n, 0n]], [0n, 0n], pubSignals);
    expect(await whitelist.isWhitelisted(zkUser.address)).to.equal(true);
    await expect(whitelist.add(zkUser.address)).to.be.revertedWith('downgrade not allowed');

    await whitelist.pause();
    await expect(whitelist.setRoot(root)).to.be.reverted;
    await whitelist.unpause();

    emitEquityLedger({
      scenario: 'EQTY-CS-01',
      source: 'whitelist',
      checks: {
        basic_allowlist_batch_supported: true,
        zk_upgrade_supported: true,
        zk_downgrade_blocked: true,
        pause_guard_enforced: true,
      },
    });
  });

  it('rejects ZK proof replay, address mismatch, and invalid verifier responses', async function () {
    const { verifier, whitelist, root, zkUser, outsider } = await deployWhitelistFixture();

    const baseSignals = [0n, BigInt(root), 22n, BigInt(zkUser.address), 0n, 0n] as const;
    await whitelist.addWithVerify(zkUser.address, [0n, 0n], [[0n, 0n], [0n, 0n]], [0n, 0n], baseSignals);

    await expect(
      whitelist.addWithVerify(zkUser.address, [0n, 0n], [[0n, 0n], [0n, 0n]], [0n, 0n], baseSignals)
    ).to.be.revertedWith('nullifier used');

    const wrongAddressSignals = [0n, BigInt(root), 23n, BigInt(zkUser.address), 0n, 0n] as const;
    await expect(
      whitelist.addWithVerify(outsider.address, [0n, 0n], [[0n, 0n], [0n, 0n]], [0n, 0n], wrongAddressSignals)
    ).to.be.revertedWith('addr mismatch');

    await verifier.setResult(false);
    const invalidSignals = [0n, BigInt(root), 24n, BigInt(outsider.address), 0n, 0n] as const;
    await expect(
      whitelist.addWithVerify(outsider.address, [0n, 0n], [[0n, 0n], [0n, 0n]], [0n, 0n], invalidSignals)
    ).to.be.revertedWith('invalid proof');
  });

  it('rejects malformed verifier configuration, root binding mistakes, and oversize batches', async function () {
    const verifierless = await deployWhitelistFixture({ verifierAddress: ethers.ZeroAddress });
    const verifierlessSignals = [0n, BigInt(verifierless.root), 31n, BigInt(verifierless.basicUser.address), 0n, 0n] as const;
    await expect(
      verifierless.whitelist.addWithVerify(
        verifierless.basicUser.address,
        [0n, 0n],
        [[0n, 0n], [0n, 0n]],
        [0n, 0n],
        verifierlessSignals
      )
    ).to.be.revertedWith('verifier !set');

    const rootless = await deployWhitelistFixture({ initialRoot: ethers.ZeroHash });
    const rootlessSignals = [0n, 0n, 32n, BigInt(rootless.basicUser.address), 0n, 0n] as const;
    await expect(
      rootless.whitelist.addWithVerify(rootless.basicUser.address, [0n, 0n], [[0n, 0n], [0n, 0n]], [0n, 0n], rootlessSignals)
    ).to.be.revertedWith('root undefined');

    const { whitelist, root, basicUser } = await deployWhitelistFixture();
    await expect(whitelist.setVerifier(ethers.ZeroAddress)).to.be.revertedWith('zero addr');

    const wrongModeSignals = [1n, BigInt(root), 33n, BigInt(basicUser.address), 0n, 0n] as const;
    await expect(
      whitelist.addWithVerify(basicUser.address, [0n, 0n], [[0n, 0n], [0n, 0n]], [0n, 0n], wrongModeSignals)
    ).to.be.revertedWith('mode != KYC');

    const wrongRootSignals = [0n, BigInt(ethers.keccak256(ethers.toUtf8Bytes('wrong-root'))), 34n, BigInt(basicUser.address), 0n, 0n] as const;
    await expect(
      whitelist.addWithVerify(basicUser.address, [0n, 0n], [[0n, 0n], [0n, 0n]], [0n, 0n], wrongRootSignals)
    ).to.be.revertedWith('root mismatch');

    const tooMany = Array.from({ length: 5001 }, (_, index) =>
      ethers.getAddress(ethers.zeroPadValue(ethers.toBeHex(index + 1), 20))
    );
    await expect(whitelist.addBatch(tooMany)).to.be.revertedWith('too many');
    await expect(whitelist.removeBatch(tooMany)).to.be.revertedWith('too many');
  });
});

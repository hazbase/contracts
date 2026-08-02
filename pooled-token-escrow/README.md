# PooledTokenEscrow

Generic many-to-one ERC-20 escrow for community pools, rewards, grants, gifts,
and other conditional payments.

## Flow

1. A creator opens an escrow for one ERC-20 token.
2. Contributors approve and call `deposit` with an idempotency key.
3. The beneficiary is fixed at creation or assigned with an EIP-712
   authorization from the escrow's immutable authorizer.
4. The beneficiary claims the whole pool before expiry, or contributors pull
   their own refunds after creator cancellation or expiry.

`expiresAt = 0` creates an indefinite escrow. Indefinite escrows only become
refundable when their creator cancels them.

## Deliberate boundaries

- ERC-20 only; native currency is not accepted.
- Product metadata and visibility stay off-chain. Only `metadataHash` is stored.
- Direct ERC-20 transfers to the contract are not attributed to an escrow.
- Rebasing tokens are unsupported.
- The token contract itself must be trusted. A malicious ERC-20 can report
  false balances or otherwise violate the ERC-20 assumptions used for accounting.
- Fee-on-transfer deposits are credited by the actual received balance. A
  transfer fee may also apply when funds leave the escrow.
- The authorizer may assign a recipient but cannot withdraw funds.
- Pausing stops deposits, claims, and refunds. The pauser cannot move funds,
  but operational procedures must prevent an unnecessary prolonged pause.
- Administrators can pause but cannot claim, redirect, or upgrade an existing
  escrow instance. New implementations are published as new factory versions;
  existing minimal-clone escrows stay pinned to the version they were created with.

## Development

```bash
npm install
npm test
```

Mainnet use requires an independent security audit and production operational
review. See [SECURITY.md](./SECURITY.md) for the trust model and release
checklist used by this repository.

## Factory publication

The implementation is published once under the existing hazBase
`ContractFactory`. Each application then deploys an immutable minimal clone and
chooses its own administrator. Copy `.env.example`, export the values, and run:

```bash
npm run implementation:publish -- --network sepolia
```

The script requires a policy-capable factory and registers the implementation
as cloneable with `initialize(address)` required. It verifies the latest
implementation after publication. Set
`POOLED_TOKEN_ESCROW_IMPLEMENTATION_ADDRESS` to register an already deployed
implementation instead of deploying another one.

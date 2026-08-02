# Security model

This document records the repository's internal security review boundaries. It
is not an independent third-party audit.

## Protected properties

- A creator and privileged roles cannot withdraw contributor funds.
- Only the assigned beneficiary can release an open, non-expired pool.
- A delayed beneficiary requires an EIP-712 or ERC-1271 authorization bound to
  the chain, escrow instance, escrow id, beneficiary, nonce, and deadline.
- Contributors pull only their own credited amount after cancellation or
  expiry.
- Contribution ids make application retries idempotent within an escrow.
- Minimal-clone instances cannot be upgraded after deployment.

## Trusted components

- The configured ERC-20 contract must behave consistently with its reported
  balances. Malicious and rebasing tokens are unsupported.
- The authorizer must sign only verified beneficiary assignments and protect
  its signing key or ERC-1271 owner.
- The pauser can temporarily block all state-changing flows, including claims
  and refunds. It cannot redirect or withdraw funds.
- An indefinite escrow depends on its creator to enable refunds if no
  beneficiary ever claims.

## Known boundaries

- Direct token transfers are not attributed and cannot be rescued by an admin.
- Fee-on-transfer tokens may charge again on release or refund.
- Negative rebases can make recorded liabilities larger than the token balance
  and prevent exits.
- Product identity, visibility, moderation, and recipient-link secrecy remain
  application responsibilities.

## Production checklist

1. Complete an independent audit before mainnet use.
2. Pin and allowlist the intended ERC-20 assets.
3. Use a contract or managed signer for the authorizer and monitor every
   beneficiary assignment.
4. Put pauser and default-admin roles behind separate controlled accounts or a
   multisig, and document unpause procedures.
5. Re-run tests, coverage, compiler warnings, and deployed-bytecode size checks
   for the exact release commit.
6. Publish and verify the implementation, factory policy, compiler settings,
   source code, and deployment addresses.
7. Monitor locked balances, claim/refund failures, expiring pools, and unusual
   contribution-id reuse.

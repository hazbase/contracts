# Physical asset rights

`PhysicalAssetToken` creates one ERC-721 right for one verified physical item.
Raw serial numbers, custody details, personal data, contracts, and delivery
records remain off-chain. Only salted commitments and fixed-size verification
digests are stored on-chain.

## Tenant deployment

Publish one reviewed implementation through `ContractFactory`, then create one
initialized clone for each issuer tenant. The deployment script can perform
both operations. For later tenants, set `PUBLISH_IMPLEMENTATION=false` and use
the same reviewed `IMPLEMENTATION_OWNER` namespace.

Required environment values:

- `CONTRACT_FACTORY_ADDRESS`
- `PHYSICAL_ASSET_TENANT_KEY`
- `PHYSICAL_ASSET_TOKEN_NAME`
- `PHYSICAL_ASSET_TOKEN_SYMBOL`
- `PHYSICAL_ASSET_ADMIN`
- `PHYSICAL_ASSET_ISSUER`
- `PHYSICAL_ASSET_GUARDIAN`
- `PHYSICAL_ASSET_REDEEMER`

Optional values:

- `PHYSICAL_ASSET_BASE_URI`
- `PHYSICAL_ASSET_TRANSFER_POLICY` (omitting it disables transfers)
- `PUBLISH_IMPLEMENTATION` (defaults to `true`)
- `IMPLEMENTATION_OWNER` (required when publishing is disabled)

Run:

```sh
npm run physical-asset:deploy -- --network sepolia
```

Use the returned `physicalAssetToken` as the RWA Ops organization setting.
Set the custody account to the approved hazBase smart account that receives
new rights. The issuer and redeemer roles should also be assigned only to an
approved smart account or controlled governance account, never a server-held
operator key. Configure a transfer policy only when rights must move between
accounts; without one, the collection fails closed and remains non-transferable.

## Lifecycle

1. RWA Ops verifies authenticity and custody off-chain.
2. The operator approves `issue` with a passkey. The item commitment becomes
   the token ID, preventing a second right for the same commitment.
3. RWA Ops registers the issued identity with the delivery service.
4. After that service confirms delivery evidence, RWA Ops prepares `redeem`.
5. The operator approves `redeem` with a passkey. The token is burned while its
   commitment, delivery digest, redemption digest, and timestamps remain as an
   immutable audit record.

# Signer

Software signing device and reference implementation of the Signer API.

More documentation coming soon!

## How to Use

```ts
import { Signer, Wallet } from '@cmdcode/signer'

// Generate or import a wallet.
const wallet = Wallet.from_xpub('xpubdeadbeef')
// Generate a signer
const signer = Signer.generate()
// Export as recoverable credential.
const cred   = signer.export_cred({ pubkey : wallet.pubkey })
// Export as nip-04 encrypted note.
const note   = signer.export_note({ pubkey : wallet.pubkey })
```

## Seed API

```ts
import { Seed } from '@cmdcode/signer'

Seed
  .gen_shards()
  .gen_words()
  .from_phrase()
  .from_random()
  .from_shards()
  .from_words()
```

## Signer API

```ts
import { Signer } from '@cmdcode/signer'

Signer
  // Import from signed credential.
  .from_cred('shared_secret')
  // Import from nip-04 nostr note.
  .from_note('shared_secret')
  // Import from a raw seed.
  .from_seed('seed')
  // Import from seed words.
  .from_words('abbadon abbadon abbadon')

const signer = Signer.from_seed('deadbeef')

signer
  // Show current path
  .path
  // Show current pubkey
  .pubkey
  // Derive a new address.
  .derive_path('/0/0')
  // Derive the next key-pair in the sequence.
  .derive_next()
  // Export as recoverable credential.
  .export_cred({ pubkey : wallet.pubkey })
  // Export as nip-04 encrypted note.
  .export_note({ pubkey : wallet.pubkey })
  // Export current pubkey as address (with format)
  .get_address({ format : 'segwit' })

const signer    = Signer.generate()
const encrypted = signer.export({ pubkey : wallet.pubkey })
```

## Wallet API

```ts
import { Wallet } from '@cmdcode/signer'

Wallet
  // Import a wallet from a raw seed.
  .from_seed("m/86h/0h/0h/rand")
  // Import a wallet from BIP39 seed words.
  .from_words("m/86h/0h/0h/rand")
  // Import a wallet from an xpub.
  .from_xpub("xpub1pdeadbeef/rand")

const wallet = Wallet.from_xpub('xpub1pdeadbeef')

wallet
  // Get current index.
  .index
  // Get current pubkey.
  .pubkey
  // Get current pubkey as address (in format).
  .address('segwit')
  // Derive a new extkey from path. 
  .derive('/0/0')
  // Export base extkey as xpub.
  .export_xpub()
  // Export base ext as descriptor.
  .export_desc()
```

## Key Derivation

When importing a key, you can choose to import a master key (with no chaincode), or a derived key (with a chaincode).

If you choose to import a master key, the signer will then derive a keypair using the default path of: `m/84'/0'/0'`

If you import an extended key, then no additional derivation is applied.

The signer will not attempt to save or keep track of a derviation path for your key, as derivation paths __cannot__ be verified without the master key anyway.

When inserting a key into a contract, there are a few things that will be stored:

- the pubkey
- the `fingerprint` (this is sort of required for BIP32)
- 

## Importing a Master Key

Master keys will be imported and derived using the following path prefix:

Example: `m/84'/0'/0'`

Using the next segment, new keys are generated using a random index value between 0x00000000 - 0x0FFFFFFF.

Example: `m/84'/0'/0'/1846522110`

The pubkey derived from this path should be added to the proposal, along with the pubkey:

Example: { members : [ [ pubkey, `m/84'/0'/0'/1846522110` ] ] }

If the user's current signing device can produce the listed pubkey using the derivation path, then the user knows that the key belongs to their wallet.

The next segment is used to signify the address type, and the final segment is used to generate addresses sequentially.

Example: `m/84'/0'/0'/1846522110/0/1`

We can easily scan this final segment and check which addresses in the proposal belong to us.

Since a new random sub-account should be generated for each proposal, the number of spent addresses for our sub-account should never exceed the number of unique addresses in the proposal.

Therefore, we should be able to generate a sequential lookup table that is equal in size to the total number of unique addresses in the contract, and any address derived from our sub-account should be within that lookup table.

Alternatively, if the address is not within the lookup table, we can check to see if an hmac signature is provided with the address.

## Import

- `from_seed`:

Import a master key from raw bytes.

- `from_phrase`:
Import a master key from a UTF-8 string.

- `from_bip39`:
Import a master key from a BIP39 seed phrase.

- `from_xprv`:
Import a private key / chaincode from a BIP32 extended key.

- `from_encrypted`:
Import a private key / chaincode from an encrypted payload.

- `from_nip04`:
Import a private key / chaincode from an encrypted note.

## Export

- `to_xpub`:
Export a private key / chaincode to a BIP32 extended key.
(for save/load from a bitcoin wallet)

- `to_encrypted`:
Export a private key / chaincode to an encrypted payload.
(for save/load from localstore)

- `to_nostr`:
Export a private key / chaincode to an encrypted note.
(for save/load from the web)

> note: use nip04?

## Methods

- `generate_key()`

- `is_`

- `derive_key` (path) => signer(self_sec, chaincode)
  Derive a signer from a derivation path.

## Strategy

User can convert a passkey into a signer in two ways:
  a. loaded from pass-encrypted payload.
  b. recovered from imported signer.

When given a proposal, user checks the following:
  1. is the ref_id located in storage (local or nip04).
  2. is the ref_id signed by the current signer (if present).

If user is a member:
  - check if `role/path` addresses match derived key
Else:
  - Generate a passkey.
  - Add passkey to proposal (to empty `role`?)
  - Derive (and add) addresses to matching `role/path`.

# Signer

Software signing device and reference implementation of the Signer API.

More documentation coming soon!

## How to Use

```ts
import { Seed, Signer } from '@cmdcode/signer'

// Generate a random seed phrase.
const words  = Seed.gen_words()

// Create a signer from seed phrase.
const signer = Signer.from_words(words)

// Export seed as a password-encrypted payload.
const encrypted = signer.export_seed('password')

// Export seed as nip-04 encrypted note.
const note = signer.export_note('hex_pubkey')

// Sign a message.
const signature = signer.sign('message')

// Generate a random account from the default wallet.
const account = signer.wallet.new_account()

// Generate a new P2W-PKH address from the account.
const address = account.new_address()

// Export the account as an xpub.
const xpub = account.xpub
```

## Seed API

```ts
import { Seed } from '@cmdcode/signer'

interface Seed {
  // Generate random seed (256 bits).
  gen_random () => Buff
  // Generate random seed words (12 / 24).
  gen_words (size :? 12 | 24) => string
  // Import a seed from a password-encrypted payload.
  from_encrypted (
    payload : Bytes,
    secret  : Bytes
  ) => Promise<Buff>
  // Import a seed from a list of seed words.
  from_words (
    words     : string | string[],
    password ?: string
  ) => Buff
  // Export a seed as a password-encrypted payload.
  to_encrypted (
    seed   : Bytes,
    secret : Bytes
  ) => Promise<Buff>
}
```

## Signer API

```ts
import { Signer } from '@cmdcode/signer'

class Signer {
  // Generate a signer from a random seed.
  static generate () => Signer
  // Import a signer from a password-encrypted payload.
  static from_encrypted (
    payload: string,
    secret: string
  ) => Promise<Signer>
  // Import a signer from a seed phrase.
  static from_words (
    words: string | string[], 
    pass?: string
  ) => Signer
  // Create a new Signer class.
  constructor (seed: Bytes) => Signer
  // Get the sha256 hash of the pubkey.
  get id     () => string
  // Get the pubkey of the signer.
  get pubkey () => string
  // Get a BIP32 wallet using the signer's internal seed.
  get wallet () => Wallet
  // Get a Diffe-Hellman shared secret from another pubkey.
  ecdh (pubkey: Bytes) => Buff
  // Export the signer's seed as a password-encrypted payload.
  export_seed (secret: string) => Promise<string>
  // Export the signer's seed as an encrypted nip-04 nostr note.
  export_note (pubkey: string) => Promise<SignedEvent>
  // Generate a pubnonce for a given message.
  gen_nonce (
    message  : Bytes, 
    options ?: SignOptions
  ) => Buff
  // Generate an HMAC signature for a given message.
  hmac (message: Bytes) => Buff
  // Create a partial signature from a musig context object.
  musign (
    context  : MusigContext, 
    auxdata  : Bytes, 
    options ?: SignOptions
  ) => Buff
  // Create a compact digital proof for a given content string.
  notarize (
    content : string, 
    params  : Params
  ): Promise<string>
  // Sign a message using BIP340-schnorr scheme.
  sign (
    message  : Bytes,
    options ?: SignOptions
  ) => string
}

interface SignOptions {
  aux         ?: Bytes | null // Add aux data to nonce generation.
  nonce_tweak ?: Bytes        // Add a tweak to the nonce value.
  key_tweak   ?: Bytes        // Add a tweak to the key value.
}
```

## Wallet API

```ts
import { Wallet } from '@cmdcode/signer'

/**
 * Wallet class for creating and managing accounts.
 */
class Wallet extends ExtendedKey {
  // Import a wallet from a raw seed.
  static from_seed  (seed: Bytes) => Wallet
  // Import a wallet from BIP39 seed words.
  static from_words (words: string | string[]) => Wallet
  // Import a wallet from an xpub.
  static from_xpub  (xpub: string) => Wallet
  // Create a wallet from an HDKey object.
  constructor (hdkey: HDKey)
  // Check if a given account exists within the wallet.
  has_account (extkey: string | HDKey) => boolean
  // Get an account key at the given account (index) number.
  get_account (acct: number, index?: number) => KeyRing
  // Generate a new account with a random index.
  new_account () => KeyRing
}

/**
 * Account-level class for extended keys.
 */
class KeyRing extends ExtendedKey {
  // Import an account from an xpub.
  static from_xpub(xpub: string) => KeyRing
  // Create an account from an HDKey object.
  constructor(hdkey: HDKey, start_idx?: number)
  // Get the current extended key for the account.
  get current () => ExtendedKey
  // Get the current child index value for the account.
  get idx () => number
  // Get a P2W-PKH address for a given child-key at index.
  get_address(index: number, network?: Network) => string
  // Get the extended key for a given child-key at index.
  get_pubkey(index: number) => ExtendedKey
  // Check if a given address exists within the account.
  has_address(address: string, limit?: number) => boolean
  // Check if a given pubkey exists within the account.
  has_pubkey(pubkey: string, limit?: number) => boolean
  // Iterate the child index and return a new P2W-PKH address.
  new_address(network?: Network) => string
  // Iterate the child index and return a new extended key.
  new_pubkey(network?: Network) => string
}

/**
 * Base class for an extended key.
 */
class ExtendedKey {
  // Convert a BIP32 HDKey into an ExtendedKey.
  constructor(hd: HDKey)
  
  get hd()     : HDKey  // Get internal HDKey object.
  get index()  : number // Get index value of current key.
  get pubkey() : string // Get pubkey value of current key.
  get xpub()   : string // Get xpub value of current key.

  // Get a P2W-PKH address for the curent key.
  address (network?: Network) => string
}
```

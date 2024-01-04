# Signer

Provides `Seed`, `Signer`, and `Wallet` tools for handling Bitcoin transactions.

> Note: This README is outdated. Updated readme coming soon!

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
import { KeyPair, Signer } from '@cmdcode/signer'

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
import { ExtendedKey, Wallet, MasterWallet } from '@cmdcode/signer'

/**
 * Base class method for defining an extended key.
 */

class ExtendedKey {
  constructor(hd : HDKey)
  
  get hd()     : HDKey  // Get internal HDKey object.
  get index()  : number // Get index value of current key.
  get pubkey() : string // Get pubkey value of current key.
  get xpub()   : string // Get xpub value of current key.

  // Get an address for the curent key.
  address (network?: Network) => string
}

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

```

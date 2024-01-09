import { HDKey }          from '@scure/bip32'
import { Buff, Bytes }    from '@cmdcode/buff'
import { get_shared_key } from '@cmdcode/crypto-tools/ecdh'

import {
  hash340,
  hmac256
} from '@cmdcode/crypto-tools/hash'

import {
  get_pubkey,
  get_seckey
} from '@cmdcode/crypto-tools/keys'

import {
  recover_key,
  sign_msg,
  verify_sig
} from '@cmdcode/crypto-tools/signer'

import { Credential } from '../types.js'

import * as assert from '../assert.js'

export function gen_credential (
  idx    : number,
  seckey : Bytes,
  xpub   : string
) : Credential {
  // Create an HD object from extended key.
  const hd = HDKey.fromExtendedKey(xpub)
  // Assert the required fields exist.
  assert.exists(hd.publicKey)
  assert.exists(hd.chainCode)
  // Config sign operation to include a recovery key.
  const opt = { recovery_key : hd.publicKey }
  // Define the credential xonly pubkey.
  const pub = get_pubkey(seckey, true)
  // Define the credential identifier.
  const id  = hmac256(seckey, pub, hd.chainCode, idx)
  // Define the credential signature.
  const sig = sign_msg(id, seckey, opt)
  // Return the full credential.
  return { id : id.hex, pub : pub.hex, sig : sig.hex }
}

export function check_claim (
  cred : Credential,
  xprv : string
) {
  // Unpack the credential object.
  const { id, pub, sig } = cred
  // Create an HD object from extended key.
  const hd = HDKey.fromExtendedKey(xprv)
  // Assert the required fields exist.
  assert.exists(hd.privateKey)
  assert.exists(hd.publicKey)
  assert.exists(hd.chainCode)
  // Define the shared secret used as seed.
  const seed  = get_shared_key(hd.privateKey, pub, true)
  // Define the nonce value using the seed.
  const nonce = hash340('BIP0340/nonce', seed, pub, id)
  // Define the k value as negated secret key.
  const k_val = get_seckey(nonce, true)
  // Define R value as xonly pubkey.
  const R_val = get_pubkey(k_val, true)
  // Slice the original R value from signature.
  const R_sig = Buff.hex(sig).slice(0, 32)
  // Return boolean result.
  return R_val.hex === R_sig.hex
}

export function claim_credential (
  cred : Credential,
  idx  : number,
  xprv : string
) : string {
  // Unpack the credential object.
  const { id, pub, sig } = cred
  // Validate the credential signature.
  if (!verify_sig(sig, id, pub)) {
    throw new Error('credential signature is invalid')
  }
  // Create an HD object from extended key.
  const hd = HDKey.fromExtendedKey(xprv)
  // Assert the required fields exist.
  assert.exists(hd.privateKey)
  assert.exists(hd.publicKey)
  assert.exists(hd.chainCode)
  // Recover the seckey from the signature.
  const seckey = recover_key(sig, id, pub, hd.privateKey)
  // Compute the xonly pubkey from the seckey.
  const pubkey = get_pubkey(seckey, true)
  // Assert the pubkeys match.
  if (pubkey.hex !== pub) {
    throw new Error('recovered pubkey is invalid: ' + pubkey.hex)
  }
  // Compute the hash identifer using hmac256.
  const hash = hmac256(seckey, pub, hd.chainCode, idx)
  // Assert the identifiers match.
  if (hash.hex !== id) {
    throw new Error('recovered id is invalid: ' + hash.hex)
  }
  // Return the secret key.
  return seckey.hex
}

export default {
  check    : check_claim,
  claim    : claim_credential,
  generate : gen_credential,
}

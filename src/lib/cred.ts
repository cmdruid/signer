import { HDKey }       from '@scure/bip32'
import { Buff, Bytes } from '@cmdcode/buff'
import { ecdhash }     from '@cmdcode/crypto-tools/ecdh'

import {
  hmac256,
  sha256
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

import { CredentialData } from '../types.js'

import * as assert from '../assert.js'

export function get_cred_id (
  pubkey : Bytes,
  index  : number,
  xpub   : string
) {
  const xpb = Buff.b58chk(xpub)
  const idx = Buff.num(index, 4)
  const img = Buff.join([ pubkey, xpb, idx ])
  return sha256(img)
}

export function has_cred_id (
  cred : CredentialData,
  rpub : Bytes,
  xpub : string
) {
  const { id, idx } = cred
  const hash = get_cred_id(rpub, idx, xpub)
  return id === hash.hex
}

export function gen_credential (
  index  : number,
  seckey : Bytes,
  xpub   : string
) : CredentialData {
  // Create an HD object from extended key.
  const hd = HDKey.fromExtendedKey(xpub)
  // Assert the required fields exist.
  assert.exists(hd.publicKey)
  assert.exists(hd.chainCode)
  // Define the index value as a non-hardened int.
  const idx   = index & 0x7FFFFFFF
  // Define the credential xonly pubkey.
  const rpub  = get_pubkey(seckey, true)
  // Define the wallet pubkey.
  const wpub  = Buff.raw(hd.publicKey)
  // Define the credential identifier.
  const id    = get_cred_id(rpub, idx, xpub)
  // Compute the credential seed.
  const cseed = hmac256(seckey, rpub, id)
  // Compute the credential secret.
  const csec  = get_seckey(cseed)
  // Compute the credential pubkey.
  const pub   = get_pubkey(csec, true).hex
  // Compute the shared seed value.
  const nseed = ecdhash(csec, wpub, true)
  // Configure the signing options.
  const opt   = { nonce_seed : nseed }
  // Define the credential signature.
  const sig   = sign_msg(id, csec, opt).hex
  // Return the full credential.
  return { id : id.hex, idx, pub, sig }
}

export function check_credential (
  cred  : CredentialData,
  xpub  : string,
  rpub ?: Bytes,
  throws = false
) {
  // Unpack the credential object.
  const { id, pub, sig } = cred
  // If root pubkey is defined, check credential id.
  if (rpub !== undefined && !has_cred_id(cred, rpub, xpub)) {
    if (throws) throw new Error('invalid membership id')
    return false
  }
  // Check credential signature.
  if (!verify_sig(sig, id, pub)) {
    if (throws) throw new Error('invalid membership')
    return false
  }
  // All checks passed.
  return true
}

export function claim_credential (
  cred : CredentialData,
  xprv : string
) : Buff {
  // Unpack the credential object.
  const { id, pub, sig } = cred
  // Create an HD object from extended key.
  const hd = HDKey.fromExtendedKey(xprv)
  // Assert the required fields exist.
  assert.exists(hd.privateKey)
  assert.exists(hd.chainCode)
  // Compute the shared seed value.
  const nseed  = ecdhash(hd.privateKey, pub, true)
  // Recover the seckey from the signature.
  const seckey = recover_key(id, pub, nseed, sig)
  // Compute the xonly pubkey from the seckey.
  const pubkey = get_pubkey(seckey, true)
  // Assert the pubkeys match.
  if (pubkey.hex !== pub) {
    throw new Error('recovered pubkey is invalid: ' + pubkey.hex)
  }
  // Return the secret key.
  return seckey
}

export default {
  check  : check_credential,
  claim  : claim_credential,
  gen_id : gen_credential,
  get_id : get_cred_id,
  has_id : has_cred_id,
}

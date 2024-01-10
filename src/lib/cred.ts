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

export function get_cred_id (rpub : Bytes, xpub : string) {
  const xpb = Buff.b58chk(xpub)
  const img = Buff.join([ rpub, xpb ])
  return sha256(img)
}

export function get_cred_msg (id : Bytes, wpub : string) {
  const wpb = Buff.b58chk(wpub)
  return Buff.join([ id, wpb ])
}

export function has_cred_id (
  cred : CredentialData,
  rpub : Bytes,
  xpub : string
) {
  const hash = get_cred_id(rpub, xpub)
  return cred.id === hash.hex
}

export function gen_credential (
  index  : number,
  seckey : Bytes,
  xpub   : string
) : CredentialData {
  const idx = index & 0x7FFFFFFF
  // Create an HD object from extended key.
  const whd = HDKey.fromExtendedKey(xpub).deriveChild(idx)
  // Assert the required fields exist.
  assert.exists(whd.publicKey)
  // Define the credential xonly pubkey.
  const rpub  = get_pubkey(seckey, true)
  // Define the credential identifier.
  const id    = get_cred_id(rpub, xpub)
  // Compute the credential seed.
  const cseed = hmac256(seckey, rpub, id)
  // Compute the credential secret.
  const csec  = get_seckey(cseed)
  // Compute the credential pubkey.
  const pub   = get_pubkey(csec, true).hex
  // Define the wallet pubkey.
  const wpk   = Buff.raw(whd.publicKey)
  // Compute the shared seed value.
  const nseed = ecdhash(csec, wpk, true)
  // Configure the signing options.
  const opt   = { nonce_seed : nseed }
  // Define the child xpub.
  const wpub  = whd.publicExtendedKey
  // Compute the signature message.
  const msg   = get_cred_msg(id, wpub)
  // Define the credential signature.
  const sig   = sign_msg(msg, csec, opt).hex
  // Return the full credential.
  return { id : id.hex, pub, sig, wpub }
}

export function verify_credential (
  cred : CredentialData,
  rpub : Bytes,
  xpub : string
) {
  // Unpack the credential object.
  const { id, pub, sig, wpub } = cred
  // If root pubkey is defined, check credential id.
  if (!has_cred_id(cred, rpub, xpub)) {
    throw new Error('invalid credential id')
  }
  // Check credential xpub.
  const xhd = HDKey.fromExtendedKey(xpub)
  const whd = HDKey.fromExtendedKey(wpub)
  if (whd.parentFingerprint !== xhd.fingerprint) {
    throw new Error('invalid credential xpub')
  }
  // Check credential signature.
  const msg = get_cred_msg(id, wpub)
  if (!verify_sig(sig, msg, pub)) {
    throw new Error('invalid credential signature')
  }
  // All checks passed.
  return true
}

export function claim_credential (
  cred : CredentialData,
  xprv : string
) : Buff {
  // Unpack the credential object.
  const { id, pub, sig, wpub } = cred
  // Create an HD object from extended key.
  const whd = HDKey.fromExtendedKey(wpub)
  const xhd = HDKey.fromExtendedKey(xprv).deriveChild(whd.index)
  // Assert the required fields exist.
  assert.exists(xhd.privateKey)
  // Compute the shared seed value.
  const nseed  = ecdhash(xhd.privateKey, pub, true)
  // Compute the signature message.
  const msg    = get_cred_msg(id, wpub)
  // Recover the seckey from the signature.
  const seckey = recover_key(msg, pub, nseed, sig)
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
  claim  : claim_credential,
  gen_id : gen_credential,
  get_id : get_cred_id,
  has_id : has_cred_id,
  verify : verify_credential
}

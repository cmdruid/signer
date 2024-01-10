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

export function get_cred_id (mspub : Bytes, mxpub : string) {
  const xbytes = Buff.b58chk(mxpub)
  const preimg = Buff.join([ mspub, xbytes ])
  return sha256(preimg)
}

export function get_cred_msg (id : Bytes, xpub : string) {
  const xbytes = Buff.b58chk(xpub)
  return Buff.join([ id, xbytes ])
}

export function has_cred_id (
  cred   : CredentialData,
  m_spub : Bytes,
  m_xpub : string
) {
  const hash = get_cred_id(m_spub, m_xpub)
  return cred.id === hash.hex
}

export function gen_credential (
  index  : number,
  seckey : Bytes,
  mxpub  : string
) : CredentialData {
  const idx = index & 0x7FFFFFFF
  // Create an HD object from extended key.
  const whd = HDKey.fromExtendedKey(mxpub).deriveChild(idx)
  // Assert the required fields exist.
  assert.exists(whd.publicKey)
  // Define the credential xonly pubkey.
  const mspub = get_pubkey(seckey, true)
  // Define the credential identifier.
  const id    = get_cred_id(mspub, mxpub)
  // Compute the credential seed.
  const cseed = hmac256(seckey, mspub, id)
  // Compute the credential secret.
  const csec  = get_seckey(cseed)
  // Compute the credential pubkey.
  const pub   = get_pubkey(csec, true).hex
  // Define the wallet pubkey.
  const wpub  = Buff.raw(whd.publicKey)
  // Compute the shared seed value.
  const nseed = ecdhash(csec, wpub, true)
  // Configure the signing options.
  const opt   = { nonce_seed : nseed }
  // Define the child xpub.
  const xpub  = whd.publicExtendedKey
  // Compute the signature message.
  const msg   = get_cred_msg(id, xpub)
  // Define the credential signature.
  const sig   = sign_msg(msg, csec, opt).hex
  // Return the full credential.
  return { id : id.hex, pub, sig, xpub }
}

export function verify_credential (
  cred  : CredentialData,
  mspub : Bytes,
  mxpub : string
) {
  // Unpack the credential object.
  const { id, pub, sig, xpub } = cred
  // If root pubkey is defined, check credential id.
  if (!has_cred_id(cred, mspub, mxpub)) {
    throw new Error('invalid credential id')
  }
  // Check credential xpub.
  const mhd = HDKey.fromExtendedKey(mxpub)
  const chd = HDKey.fromExtendedKey(xpub)
  if (chd.parentFingerprint !== mhd.fingerprint) {
    throw new Error('invalid credential xpub')
  }
  // Check credential signature.
  const msg = get_cred_msg(id, xpub)
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
  const { id, pub, sig, xpub } = cred
  // Create an HD object from extended key.
  const chd = HDKey.fromExtendedKey(xpub)
  const mhd = HDKey.fromExtendedKey(xprv).deriveChild(chd.index)
  // Assert the required fields exist.
  assert.exists(mhd.privateKey)
  // Compute the shared seed value.
  const nseed  = ecdhash(mhd.privateKey, pub, true)
  // Compute the signature message.
  const msg    = get_cred_msg(id, xpub)
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

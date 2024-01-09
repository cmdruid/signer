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
  sign_msg
} from '@cmdcode/crypto-tools/signer'

import { Credential } from '../types.js'

import * as assert from '../assert.js'

export function gen_credential (
  idx    : number,
  seckey : Bytes,
  xpub   : string
) : Credential {
  const hd = HDKey.fromExtendedKey(xpub)
  assert.exists(hd.publicKey)
  assert.exists(hd.chainCode)
  const opt = { recovery_key : hd.publicKey }
  const pub = get_pubkey(seckey)
  const id  = hmac256(seckey, pub, hd.chainCode, idx)
  const sig = sign_msg(id, seckey, opt)
  return { id : id.hex, pub : pub.hex, sig : sig.hex }
}

export function check_claim (
  cred : Credential,
  xprv : string
) {
  const { id, pub, sig } = cred
  const hd = HDKey.fromExtendedKey(xprv)
  assert.exists(hd.privateKey)
  assert.exists(hd.publicKey)
  assert.exists(hd.chainCode)
  const seed  = get_shared_key(hd.privateKey, pub, true)
  const nonce = hash340('BIP0340/nonce', seed, pub, id)
  const k_val = get_seckey(nonce, true)
  const R_val = get_pubkey(k_val, true)
  const R_sig = Buff.hex(sig).slice(0, 32)
  return R_val.hex === R_sig.hex
}

export function claim_credential (
  cred : Credential,
  idx  : number,
  xprv : string
) : string {
  const { id, pub, sig } = cred
  const hd = HDKey.fromExtendedKey(xprv)
  assert.exists(hd.privateKey)
  assert.exists(hd.publicKey)
  assert.exists(hd.chainCode)
  const seckey = recover_key(sig, id, pub, hd.privateKey)
  const pubkey = get_pubkey(seckey)
  const hash   = hmac256(seckey, pub, hd.chainCode, idx)
  if (pubkey.hex !== pub) {
    throw new Error('recovered pubkey is invalid: ' + pubkey.hex)
  }
  if (hash.hex !== id) {
    throw new Error('recovered id is invalid: ' + hash.hex)
  }
  return seckey.hex
}

export default {
  check    : check_claim,
  claim    : claim_credential,
  generate : gen_credential,
}

import { Buff, Bytes }    from '@cmdcode/buff'
import { cbc }            from '@noble/ciphers/aes'
import { wordlist }       from '@scure/bip39/wordlists/english'
import { get_shared_key } from '@cmdcode/crypto-tools/ecdh'
import { get_seckey }     from '@cmdcode/crypto-tools/keys'
import { HDKey }          from '@scure/bip32'

import {
  hmac256,
  pkdf512
} from '@cmdcode/crypto-tools/hash'

import {
  combine_shares,
  create_shares
} from '@cmdcode/crypto-tools/shamir'

import {
  generateMnemonic,
  validateMnemonic,
  mnemonicToSeedSync
} from '@scure/bip39'

import * as assert from '../assert.js'

export function ecdh (
  seckey : Bytes,
  pubkey : Bytes
) {
  const shared = get_shared_key(seckey, pubkey)
  return shared.slice(1, 33)
}

export function decrypt (
  payload : Bytes,
  secret  : Bytes,
  vector  : Bytes
) {
  const dat = Buff.bytes(payload)
  const sec = Buff.bytes(secret)
  const vec = Buff.bytes(vector)
  const dec = cbc(sec, vec).decrypt(dat)
  return Buff.raw(dec)
}

export function encrypt (
  payload : Bytes,
  secret  : Bytes,
  vector  : Bytes
) {
  const dat = Buff.bytes(payload)
  const sec = Buff.bytes(secret)
  const vec = Buff.bytes(vector)
  return Buff.raw(cbc(sec, vec).encrypt(dat))
}

export function gen_seckey () {
  const seed = Buff.random(32)
  return get_seckey(seed)
}

export function gen_words (size ?: 12 | 24) : string[] {
  const bits = (size === 24) ? 256 : 128
  return generateMnemonic(wordlist, bits).split(' ')
}

export function gen_shares (
  thold : number,
  total : number
) {
  const seed = Buff.random(32)
  return create_shares(seed, thold, total)
}

export function get_ref (
  kid    : Bytes,
  pubkey : Bytes,
  seckey : Bytes
) {
  const ref = hmac256(seckey, kid, pubkey)
  return ref.slice(0, 16)
}

export function get_vec (
  payload : Bytes,
  secret  : Bytes,
  size = 16
) {
  return hmac256(secret, payload).slice(0, size)
}

export const import_seed = {
  from_raw : (bytes : Bytes, password ?: string) => {
    const salt = Buff.str('seed' + password)
    return pkdf512(bytes, salt)
  },
  from_shares : (shares : Bytes[]) => {
    return combine_shares(shares)
  },
  from_words : (
    words     : string | string[],
    password ?: string
  ) => {
    if (Array.isArray(words)) {
      words = words.join(' ')
    }
    validateMnemonic(words, wordlist)
    return mnemonicToSeedSync(words, password)
  }
}

export function parse_xpub (xpub : string) {
  const hd = HDKey.fromExtendedKey(xpub)
  assert.exists(hd.publicKey)
  assert.exists(hd.chainCode)
  return {
    code    : Buff.raw(hd.chainCode).hex,
    depth   : hd.depth,
    fprint  : hd.parentFingerprint,
    index   : hd.index,
    pubkey  : Buff.raw(hd.publicKey).hex,
    version : hd.versions.public
  }
}
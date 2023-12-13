import { Buff, Bytes } from '@cmdcode/buff'
import { wordlist }    from '@scure/bip39/wordlists/english'

import {
  hmac512,
  pkdf256
} from '@cmdcode/crypto-tools/hash'

import {
  get_pubkey,
  get_seckey
} from '@cmdcode/crypto-tools/keys'

import {
  combine_shares,
  create_shares
} from '@cmdcode/crypto-tools/shamir'

import {
  encrypt,
  decrypt
} from '@cmdcode/crypto-tools/cipher'

import {
  generateMnemonic,
  validateMnemonic,
  mnemonicToSeedSync
} from '@scure/bip39'

import * as assert from '../assert.js'

export async function decrypt_data (
  payload : Bytes,
  secret  : Bytes
) {
  const bytes  = Buff.bytes(payload)
  assert.size(bytes, 64)
  const vector = bytes.slice(0, 16)
  const data   = bytes.slice(16)
  const enckey = pkdf256(secret, vector)
  return decrypt(enckey, data, vector, 'AES-CBC')
}

export async function encrypt_data (
  seckey : Bytes,
  secret : Bytes
) {
  const bytes   = Buff.bytes(seckey)
  const vector  = Buff.random(16)
  const enckey  = pkdf256(secret, vector)
  const payload = await encrypt(enckey, bytes, vector, 'AES-CBC')
  return Buff.join([ vector, payload ])
}

export async function encrypt_content (
  content : string,
  secret  : Bytes
) {
  const encoded = Buff.str(content)
  const vector  = Buff.random(16)
  const payload = await encrypt(secret, encoded, vector, 'AES-CBC')
  return payload.b64url + '?iv=' + vector.b64url
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
  prev_pubkey : Bytes,
  next_seckey : Bytes
) {
  const mstkey = Buff.bytes(prev_pubkey)
  const seckey = Buff.bytes(next_seckey)
  const pubkey = get_pubkey(seckey, true)
  return hmac512(seckey, mstkey, pubkey).slice(0, 32)
}

export const import_key = {
  from_shares : (
  shares : Bytes[]
  ) => {
    const seed = combine_shares(shares)
    return get_seckey(seed)
  },
  from_words : (
    words     : string | string[],
    password ?: string
  ) => {
    if (Array.isArray(words)) {
      words = words.join(' ')
    }
    validateMnemonic(words, wordlist)
    const seed = mnemonicToSeedSync(words, password)
    return get_seckey(seed)
  }
}

export function parse_passkey (key : Bytes) {
  const bytes   = Buff.bytes(key)
  assert.ok(bytes.length >= 96, 'invalid passkey length: ' + bytes.length)
  const pubkey  = bytes.slice(0, 32).hex
  const id      = bytes.slice(32, 64).hex
  const ref     = bytes.slice(64, 96).hex
  const payload = (bytes.length > 96)
    ? bytes.slice(96).hex
    : null
  return { pubkey, id, ref, payload }
}

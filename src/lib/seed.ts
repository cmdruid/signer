import { Buff, Bytes } from '@cmdcode/buff'
import { wordlist }    from '@scure/bip39/wordlists/english'
import { pkdf256 }     from '@cmdcode/crypto-tools/hash'

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

export function gen_random () {
  return Buff.random(32)
}

export function gen_words (size ?: 12 | 24) : string[] {
  const bits = (size === 24) ? 256 : 128
  return generateMnemonic(wordlist, bits).split(' ')
}

export async function from_encrypted (
  payload : Bytes,
  secret  : Bytes
) {
  const msg = Buff.bytes(payload)
  assert.size(msg, 64)
  const vector = msg.slice(0, 16)
  const data   = msg.slice(16)
  const seckey = pkdf256(secret, vector)
  return decrypt(seckey, data, vector, 'AES-CBC')
}

export function from_words (
  words     : string | string[],
  password ?: string
) {
  if (Array.isArray(words)) {
    words = words.join(' ')
  }
  validateMnemonic(words, wordlist)
  return Buff.raw(mnemonicToSeedSync(words, password))
}

export async function to_encrypted (
  seed   : Bytes,
  secret : Bytes
) {
  const bytes   = Buff.bytes(seed)
  const vector  = Buff.random(16)
  const seckey  = pkdf256(secret, vector)
  const payload = await encrypt(seckey, bytes, vector, 'AES-CBC')
  return Buff.join([ vector, payload ])
}

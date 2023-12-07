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

export function generate () {
  return Buff.random(32)
}

export function gen_words (size ?: 12 | 24) : string[] {
  const bits = (size === 12) ? 128 : 256
  return generateMnemonic(wordlist, bits).split(' ')
}

export async function encrypt_seed (
  seed   : Bytes,
  secret : Bytes
) {
  const bytes   = Buff.bytes(seed)
  const vector  = Buff.random(16)
  const seckey  = pkdf256(secret, vector)
  const payload = await encrypt(seckey, bytes, vector, 'AES-CBC')
  return Buff.join([ vector, payload ])
}

export async function from_aes (
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
  phrase    : string | string[],
  password ?: string
) {
  if (Array.isArray(phrase)) {
    phrase = phrase.join(' ')
  }
  validateMnemonic(phrase, wordlist)
  return mnemonicToSeedSync(phrase, password)
}

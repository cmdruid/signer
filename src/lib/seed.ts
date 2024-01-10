import { Buff, Bytes } from '@cmdcode/buff'
import { wordlist }    from '@scure/bip39/wordlists/english'
import { pkdf512 }     from '@cmdcode/crypto-tools/hash'

import {
  combine_shares,
  create_shares
} from '@cmdcode/crypto-tools/shamir'

import {
  generateMnemonic,
  validateMnemonic,
  mnemonicToSeedSync
} from '@scure/bip39'

export function import_seed_data (
  data      : Bytes, 
  password ?: string
) {
  const salt = Buff.str('seed' + password)
  return pkdf512(data, salt)
}

export function import_seed_char (
  char  : string,
  salt ?: string
) {
  const bchar = Buff.str(char)
  const bsalt = Buff.str('seed' + salt)
  return pkdf512(bchar, bsalt)
}

export function import_seed_shares (shares : Bytes[]) {
  return combine_shares(shares)
}

export function import_seed_words (
  words     : string | string[],
  password ?: string
) {
  if (Array.isArray(words)) {
    words = words.join(' ')
  }
  validateMnemonic(words, wordlist)
  return mnemonicToSeedSync(words, password)
}

export function gen_seed_words (size ?: 12 | 24) : string[] {
  const bits = (size === 24) ? 256 : 128
  return generateMnemonic(wordlist, bits).split(' ')
}

export function gen_seed_shares (
  thold : number,
  total : number
) {
  const seed = Buff.random(32)
  return create_shares(seed, thold, total)
}

export default {
  generate : {
    random : (size ?: number) => Buff.random(size),
    shares : gen_seed_shares,
    words  : gen_seed_words
  },
  import : {
    from_char   : import_seed_char,
    from_data   : import_seed_data,
    from_shares : import_seed_shares,
    from_words  : import_seed_words
  }
}

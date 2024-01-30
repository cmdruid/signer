import { Buff, Bytes } from '@cmdcode/buff'
import { pkdf256 }     from '@cmdcode/crypto-tools/hash'
import { get_pubkey }  from '@cmdcode/crypto-tools/keys'
import { HDKey }       from '@scure/bip32'
import { VERSIONS }    from '../const.js'

import {
  decrypt_cbc,
  encrypt_cbc
} from '@cmdcode/crypto-tools/cipher'

export function parse_extkey (extkey : string) {
  if (extkey.startsWith('xpub')) {
    return HDKey.fromExtendedKey(extkey, VERSIONS['main'])
  } else if (extkey.startsWith('tpub')) {
    return HDKey.fromExtendedKey(extkey, VERSIONS['test'])
  } else {
    throw new Error('unrecognized prefix: ' + extkey.slice(0, 4))
  }
}

export function derive_secret (
  password : Bytes,
  vector   : Bytes
) {
  return pkdf256(password, vector, 2048)
}

export function decrypt_key (
  payload  : Bytes,
  password : Bytes
) {
  const bytes  = Buff.bytes(payload)
  const vector = bytes.subarray(0, 16)
  const data   = bytes.subarray(16)
  const secret = derive_secret(password, vector)
  return decrypt_cbc(data, secret, vector)
}

export function encrypt_key (
  password : Bytes,
  seckey   : Bytes
) {
  const vector  = get_pubkey(seckey, true).slice(0, 16)
  const secret  = derive_secret(password, vector)
  const encdata = encrypt_cbc(seckey, secret, vector)
  return Buff.join([ vector, encdata ])
}

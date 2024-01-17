import { Buff, Bytes } from '@cmdcode/buff'
import { pkdf256 }     from '@cmdcode/crypto-tools/hash'
import { get_pubkey }  from '@cmdcode/crypto-tools/keys'
import { cbc }         from '@noble/ciphers/aes'
import { HDKey }       from '@scure/bip32'
import { VERSIONS }    from '../const.js'

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
  pubkey   : Bytes
) {
  return pkdf256(password, pubkey, 2048)
}


export function decrypt_key (
  payload  : Bytes,
  password : Bytes
) {
  const bytes  = Buff.bytes(payload)
  const pubkey = bytes.subarray(0, 32)
  const data   = bytes.subarray(32)
  const secret = derive_secret(password, pubkey)
  return decrypt(data, secret, pubkey)
}

export function encrypt_key (
  password : Bytes,
  seckey   : Bytes
) {
  const pubkey  = get_pubkey(seckey)
  const secret  = derive_secret(password, pubkey)
  const encdata = encrypt(secret, secret, pubkey)
  return Buff.join([ pubkey, encdata ])
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

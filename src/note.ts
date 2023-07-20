import { Buff } from '@cmdcode/buff-utils'
import { ecc }  from '@cmdcode/crypto-utils'

import {
  DataSigner,
  Signed
} from './types.js'

export const now = () : number => {
  return Math.floor(Date.now() / 1000)
}

export function notarize_data <T> (
  data   : T,
  pubkey : string,
  signer : DataSigner
) : Signed<T> {
  const content = JSON.stringify(data),
        stamp   = now(),
        image   = [ 0, pubkey, stamp, 20000, [], content ],
        id      = Buff.json(image).digest.hex,
        sig     = signer(id)
  return { id, pubkey, sig, stamp, ...data }
}

export function verify_note <T> (
  note : Signed<T>
) : boolean {
  const { id, sig, pubkey, stamp, ...data } = note
  const content  = JSON.stringify(data)
  const image    = [ 0, pubkey, stamp, 20000, [], content ]
  const hash     = Buff.json(image).digest.hex
  return (id === hash && ecc.verify(sig, id, pubkey))
}

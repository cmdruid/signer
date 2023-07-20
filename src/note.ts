import { Buff } from '@cmdcode/buff-utils'
import { ecc }  from '@cmdcode/crypto-utils'

import {
  SignData,
  Signed
} from './types.js'

export const now = () : number => {
  return Math.floor(Date.now() / 1000)
}

export function notarize_data <T> (
  data   : T,
  pubkey : string,
  signer : SignData
) : Signed<T> {
  const content   = JSON.stringify(data),
        timestamp = now(),
        image     = [ 0, pubkey, timestamp, 20000, [], content ],
        id        = Buff.json(image).digest.hex,
        sig       = signer(id)
  return { id, pubkey, sig, timestamp, ...data }
}

export function verify_note <T> (
  note : Signed<T>
) : boolean {
  const { id, sig, pubkey, timestamp, ...data } = note
  const content  = JSON.stringify(data)
  const image    = [ 0, pubkey, timestamp, 20000, [], content ]
  const hash     = Buff.json(image).digest.hex
  return (id === hash && ecc.verify(sig, id, pubkey))
}

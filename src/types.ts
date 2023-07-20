import { Bytes }  from '@cmdcode/buff-utils'
import { Signer } from './Signer.js'

export type Signed<T> = Signature & T
export type SignData  = (message : Bytes) => string

export interface SignerAPI extends Signer {}

export interface Signature {
  id        : string
  pubkey    : string
  sig       : string
  timestamp : number
}

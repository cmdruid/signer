import { Bytes }  from '@cmdcode/buff-utils'
import { Signer } from './Signer.js'

export type Literal    = string | number | boolean | null
export type Signed<T>  = ProofData & T
export type DataSigner = (content : Bytes) => string

export type Endorsement = [
  ref    : string,
  pubkey : string,
  id     : string,
  sig    : string,
  stamp  : number
]

export interface SignerAPI extends Signer {}

export interface Event {
  content    : string
  created_at : number
  id         : string
  kind       : number
  pubkey     : string
  sig        : string
  tags       : string[][]
}

export interface ProofData {
  id     : string
  pubkey : string
  ref    : string
  sig    : string
  stamp  : number
}

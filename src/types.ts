import { Bytes }  from '@cmdcode/buff-utils'
import { Signer } from './Signer.js'

export type Signed<T>  = ProofData & T
export type DataSigner = (content : Bytes) => string

export type Endorsement = [
  hash   : string,
  pubkey : string,
  stamp  : number,
  id     : string,
  sig    : string,
]

export interface SignerAPI extends Signer {}

export interface ProofData {
  id     : string
  pubkey : string
  sig    : string
  stamp  : number
}

import { Bytes }   from '@cmdcode/buff'
import { Network } from '@scrow/tapscript'

export type Literal = string | number | boolean | null
export type Params  = Literal[][] | Record<string, Literal>

// export interface ExtPubkey {
//   code    : string
//   depth   : number
//   fprint  : number
//   index   : number
//   pubkey  : string
//   version : number
// }

// export interface KeyConfig {
//   seckey : Bytes
//   kid   ?: Bytes
// }

// export interface KeyCredential {
//   kid     : Bytes
//   pub     : Bytes
//   ref     : Bytes
//   seckey  : Bytes
//   xpub    : string
// }

// export interface PubCredential {
//   kid : string
//   pay : string
//   pub : string
//   ref : string
//   vec : string
// }

// export interface PayloadConfig {
//   iv     ?: Bytes
//   pubkey ?: Bytes
// }

export interface AddressConfig {
  format  ?: string
  index   ?: number
  network ?: Network
}

export interface ProofConfig {
  content     : string
  created_at ?: number
  kind       ?: number
  options    ?: SignOptions
  params     ?: Params
  seckey      : Bytes
}

export interface ProofPolicy {
  since  ?: number
  throws ?: boolean
  until  ?: number
}

// export interface WalletConfig {
//   network   : Network
//   start_idx : number
// }

export interface ProofData {
  cat  : number
  hex  : string
  knd  : number
  pid  : string
  pub  : string
  qry ?: string
  sig  : string
  tag  : string[][]
}

export interface SignedEvent {
  pubkey     : string
  created_at : number
  id         : string
  sig        : string
  kind       : number
  content    : string
  tags       : string[][]
}

export interface SignOptions {
  aux         ?: Bytes | null
  adaptor     ?: string
  nonce_tweak ?: Bytes
  key_tweak   ?: Bytes
  recovery    ?: Bytes
  throws      ?: boolean
}

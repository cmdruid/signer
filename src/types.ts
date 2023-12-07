import { Buff, Bytes } from '@cmdcode/buff'

export type Literal = string | number | boolean | null
export type Params  = Literal[][] | Record<string, Literal>

export interface KeyLink {
  hd_code : Buff
  hd_path : string
  prev_pk : Buff
  pubkey  : Buff
  root_pk : Buff | null
  seckey  : Buff | null
}

export interface ProofConfig {
  since  ?: number
  throws ?: boolean
  until  ?: number
}

export interface ProofData {
  pub    : string
  pid    : string
  sig    : string
  params : string[][]
}

export interface SignedEvent {
  pubkey     : string
  created_at : number
  id         : string
  sig        : string
  kind       : number
  content    : string
  tags       : Literal[][]
}

export interface SignOptions {
  aux         ?: Bytes | null
  adaptor     ?: string
  nonce_tweak ?: Bytes
  key_tweak   ?: Bytes
  recovery    ?: Bytes
  throws      ?: boolean
}

export interface SignerData {
  code     ?: Bytes
  path     ?: string
  prev     ?: Bytes
  recovery ?: Bytes
  seckey    : Bytes
}

export interface ExtKey {
  prefix  : number // 4  bytes
  depth   : number // 1  byte
  fprint  : number // 4  bytes
  index   : number // 4  bytes
  code    : string // 32 bytes
  type    : number // 1  bytes
  key     : string // 32 bytes
  seckey ?: string
  pubkey  : string
}
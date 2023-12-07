import { Bytes } from '@cmdcode/buff'

export type Literal = string | number | boolean | null
export type Params  = Literal[][] | Record<string, Literal>

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

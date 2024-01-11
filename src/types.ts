import { Bytes }   from '@cmdcode/buff'
import { Network } from '@scrow/tapscript'

export type Literal = string | number | boolean | null
export type Params  = Literal[][] | Record<string, Literal>

export interface CredentialData {
  id   : string
  pub  : string
  sig  : string
  xpub : string
}

export interface CredConfig {
  idx  ?: number
  xpub ?: string
}

export interface KeyConfig {
  seed    : Bytes
  id     ?: Bytes
  idxgen ?: () => number
  xpub   ?: string
}

export interface AddressConfig {
  format  ?: string
  index   ?: number
  network ?: Network
}

export interface TokenOptions {
  created_at ?: number
  kind       ?: number
  options    ?: SignOptions
  params     ?: Params
}

export interface TokenPolicy {
  since  ?: number
  throws ?: boolean
  until  ?: number
}

export interface TokenData {
  cat  : number
  hex  : string
  knd  : number
  pid  : string
  pub  : string
  qry ?: string
  sig  : string
  str  : string
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
  aux          ?: Bytes | null
  adaptor      ?: string
  nonce_tweak  ?: Bytes
  key_tweak    ?: Bytes
  recovery_key ?: Bytes
  throws       ?: boolean
}

export interface WalletConfig {
  seed      : Bytes,
  network  ?: Network,
  path     ?: string,
  versions ?: { private : number, public : number }
}

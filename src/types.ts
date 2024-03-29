import { Buff, Bytes }  from '@cmdcode/buff'
import { MusigContext } from '@cmdcode/musig2'

export type Literal = string | number | boolean | null
export type Network = "main" | "testnet" | "signet" | "regtest" | "mutiny"
export type Params  = Literal[][] | Record<string, Literal>

export type HmacTypes  = '256' | '512'
export type SignDevice = (msg : Bytes) => string

export type MusignDevice = (
  ctx : MusigContext, 
  aux : Bytes, 
  opt : SignOptions
) => Buff

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
  path   ?: string
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

export interface SignerAPI {
  id        : string
  pubkey    : string
  gen_nonce : (data : Bytes) => Buff
  hmac      : (size : '256' | '512', ...bytes : Bytes[]) => Buff
  musign    : MusignDevice
  sign      : SignDevice
}

export interface CredentialAPI extends SignerAPI {
  backup    : (password : Bytes) => Bytes
  has_id    : (id : Bytes, pubkey : Bytes) => boolean
  get_id    : (id : Bytes) => CredentialAPI
  gen_cred  : (idx : number, xpub : string) => CredentialData
  gen_token : (content : string) => string
}

export interface WalletAPI {
  xpub : string
  has_account : (extkey : string) => boolean
  get_account : (id : Bytes) => WalletAPI
  has_address : (addr : string, limit ?: number) => boolean
  new_address : () => string
}

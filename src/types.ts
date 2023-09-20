import { Bytes } from '@cmdcode/buff'

export interface SignerOptions {
  aux         ?: Bytes | null
  adaptor     ?: string
  nonce_tweak ?: Bytes
  key_tweak   ?: Bytes
  throws      ?: boolean
}

export interface SignerConfig {
  hd_code  ?: Bytes
  hd_path  ?: string
  recovery ?: Bytes
}

import { Bytes }       from '@cmdcode/buff-utils'
import { SignOptions } from '@cmdcode/crypto-utils'

export type SignerOptions = Partial<SignerConfig>

const MSG_MIN_VALUE = 0xFFn ** 24n

export interface SignerConfig {
  chain_code ?: Bytes
  msg_min     : bigint
  path       ?: string
  sign_opt   ?: SignOptions
  recovery   ?: Bytes
  xonly       : boolean
}

const SIGNER_DEFAULTS : SignerConfig = {
  msg_min : MSG_MIN_VALUE,
  xonly   : true
}

export function signer_config (
  options : SignerOptions = {}
) : SignerConfig {
  return { ...SIGNER_DEFAULTS, ...options  }
}

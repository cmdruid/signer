import { Buff, Bytes } from '@cmdcode/buff-utils'

import * as musig from '@cmdcode/musig2'

import {
  hd,
  ecdh,
  hash,
  keys,
  signer
} from '@cmdcode/crypto-utils'

import * as assert from './assert.js'

type MusigContext = musig.MusigContext

export interface SignOptions {
  aux     ?: Bytes
  adaptor ?: string
  tweak   ?: Bytes
  throws  ?: boolean
}

export interface SignerOptions extends SignOptions {
  hd_code  ?: Bytes
  hd_path  ?: string
  recovery ?: Bytes
}

const MSG_MIN_VALUE = 0xFFn ** 24n

export class Signer {
  static generate (
    opt ?: SignerOptions
  ) : Signer {
    const sec = keys.gen_seckey()
    return new Signer(sec, opt)
  }

  readonly _pubkey : Buff
  readonly _seckey : Buff
  readonly _chain ?: Buff
  readonly _config : SignerOptions

  constructor (
    secret  : Bytes,
    options : SignerOptions = {}
  ) {
    const { hd_path, hd_code } = options
    if (typeof hd_path === 'string') {
      // Derive new key and code from path.
      const { seckey, code } = hd.derive(hd_path, secret, hd_code, true)
      // Assert that the secret key exists.
      assert.exists(seckey)
      // Apply new key as secret.
      secret = seckey
      // Apply new chain code to config.
      this._chain = code
    }

    this._seckey = keys.get_seckey(secret)
    this._pubkey = keys.get_pubkey(this._seckey, true)
    this._config = options
  }

  get pubkey () : Buff {
    return this._pubkey
  }

  _signer (opt ?: SignOptions) : (msg : Bytes) => Buff {
    const config = { ...this._config, ...opt }
    return (msg : Bytes) : Buff => {
      assert.size(msg, 32)
      assert.min_byte_value(msg, MSG_MIN_VALUE)
      return signer.sign(msg, this._seckey, config)
    }
  }

  derive (path : string) : Signer {
    const config = { ...this._config, path }
    return new Signer(this._seckey, config)
  }

  ecdh (pubkey : Bytes) : Buff {
    return ecdh.get_shared_key(this._seckey, pubkey)
  }

  gen_nonce (message : Bytes) : Buff {
    return signer.gen_nonce(
      message,
      this._seckey,
      this._pubkey,
      this._config
    )
  }

  hmac (message : Bytes) : Buff {
    return hash.hmac512(this._seckey, message)
  }

  sign (
    message  : Bytes,
    options ?: SignOptions
  ) : Buff {
    return this._signer(options)(message)
  }

  musign (
    context   : MusigContext,
    sec_nonce : Bytes,
    aux_data ?: Bytes
  ) : Buff {
    assert.size(sec_nonce, 32)
    const { group_pubkey } = context
    const int_nonce = this.gen_nonce(aux_data ?? group_pubkey)
    const ext_nonce = Buff.join([ int_nonce, sec_nonce ])
    return musig.sign.with_ctx(context, this._seckey, ext_nonce)
  }

  with (opt : SignOptions) : Signer {
    const config = { ...this._config, ...opt }
    return new Signer(this._seckey, config)
  }
}

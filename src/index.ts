import { Buff, Bytes } from '@cmdcode/buff-utils'

import { MusigContext, sign } from '@cmdcode/musig2'

import {
  hd,
  ecdh,
  hash,
  keys,
  signer,
  SignOptions
} from '@cmdcode/crypto-utils'

import * as assert from './assert.js'

export interface SignerOptions extends SignOptions {
  hd_code ?: Bytes
  hd_path ?: string
  rec_key ?: Bytes
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
    const { hd_path, hd_code, xonly } = options
    if (typeof hd_path === 'string') {
      // Derive new key and code from path.
      const { seckey, code } = hd.derive(hd_path, secret, hd_code, true)
      //
      assert.exists(seckey)
      // Apply new key as secret.
      secret = seckey
      // Apply new chain code to config.
      this._chain = code
    }

    this._seckey = keys.get_seckey(secret)
    this._pubkey = keys.get_pubkey(this._seckey, xonly)
    this._config = options
  }

  _signer (config : SignerOptions) {
    return (content : Bytes) : Buff => {
      const msg = Buff.bytes(content)
      assert.size(msg, 32)
      assert.min_byte_value(msg, MSG_MIN_VALUE)
      return signer.sign(content, this._seckey, config)
    }
  }

  derive (path : string) : Signer {
    const config = { ...this._config, path }
    return new Signer(this._seckey, config)
  }

  ecdh (pubkey : Bytes) : Buff {
    return ecdh.get_shared_key(this._seckey, pubkey)
  }

  gen_nonce (
    message : Bytes,
    pubkey ?: Bytes
  ) : Buff {
    return signer.gen_nonce(
      message,
      this._seckey,
      pubkey ?? this._pubkey,
      this._config
    )
  }

  hmac (message : Bytes) : Buff {
    return hash.hmac512(this._seckey, message)
  }

  sign (message : Bytes) : Buff {
    return this._signer(this._config)(message)
  }

  musign (
    context   : MusigContext,
    sec_nonce : Bytes
  ) : Buff {
    return sign.with_ctx(context, this._seckey, sec_nonce)
  }
}

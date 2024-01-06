import { Buff, Bytes }  from '@cmdcode/buff'
import { KeyPair }      from './keypair.js'

import {
  get_pubkey
} from '@cmdcode/crypto-tools/keys'

import {
  MusigContext,
  musign
} from '@cmdcode/musig2'

import {
  gen_nonce,
  sign_msg
} from '@cmdcode/crypto-tools/signer'

import { SignOptions } from '../types.js'

import * as assert from '../assert.js'

const MSG_MIN_VALUE = 0xFFn ** 24n

export class Signer extends KeyPair {

  static generate () {
    const seckey = Buff.random(32)
    return new Signer(seckey)
  }

  constructor (
    seckey : Bytes,
    kid   ?: Bytes
  ) {
    super(seckey, kid)
  }

  _gen_nonce (opt ?: SignOptions) {
    const config = { aux: null, ...opt }
    return (msg : Bytes) : Buff => {
      return gen_nonce(msg, this._seckey, config)
    }
  }

  _musign (opt ?: SignOptions) {
    return (
      context : MusigContext,
      auxdata : Bytes
    ) : Buff => {
      const sns = Buff
        .parse(auxdata, 32, 64)
        .map(e => this._gen_nonce(opt)(e))
      return musign(context, this._seckey, Buff.join(sns))
    }
  }

  _sign (opt ?: SignOptions) {
    return (msg : Bytes) : string => {
      assert.size(msg, 32)
      assert.min_value(msg, MSG_MIN_VALUE)
      return sign_msg(msg, this._seckey, opt).hex
    }
  }

  gen_nonce (
    message  : Bytes,
    options ?: SignOptions
  ) : Buff {
    const sn = this._gen_nonce(options)(message)
    return get_pubkey(sn, true)
  }

  musign (
    context  : MusigContext,
    auxdata  : Bytes,
    options ?: SignOptions
  ) : Buff {
    return this._musign(options)(context, auxdata)
  }

  sign (
    message  : Bytes,
    options ?: SignOptions
  ) : string {
    return this._sign(options)(message)
  }
}

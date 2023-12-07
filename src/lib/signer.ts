import { Buff, Bytes }     from '@cmdcode/buff'
import { hmac512, sha256 } from '@cmdcode/crypto-tools/hash'
import { get_shared_key }  from '@cmdcode/crypto-tools/ecdh'
import { encrypt }         from '@cmdcode/crypto-tools/cipher'
import { now }             from '../util.js'

import {
  create_event,
  create_proof
} from './proof.js'

import {
  encrypt_seed,
  from_aes,
  from_words
} from './seed.js'

import {
  MusigContext,
  musign
} from '@cmdcode/musig2'

import {
  get_pubkey,
  get_seckey
} from '@cmdcode/crypto-tools/keys'

import {
  gen_nonce,
  sign_msg
} from '@cmdcode/crypto-tools/signer'

import { Params, SignOptions } from '../types.js'

import * as assert from '../assert.js'

const MSG_MIN_VALUE = 0xFFn ** 24n

export class Signer {

  static generate () {
    const seed = Buff.random(32)
    return new Signer(seed)
  }

  static async from_aes (
    payload : string,
    secret  : string
  ) {
    const bytes   = Buff.hex(payload)
    const encoded = Buff.str(secret)
    const seed    = await from_aes(bytes, encoded)
    return new Signer(seed)
  }

  static from_words (
    words : string | string[]
  ) {
    const seed = from_words(words)
    return new Signer(seed)
  }

  readonly _pubkey : Buff
  readonly _seckey : Buff
  readonly _seed   : Buff

  constructor (seed : Bytes) {
    this._seed   = Buff.bytes(seed)
    this._seckey = get_seckey(seed)
    this._pubkey = get_pubkey(this._seckey, true)
  }

  get id () : string {
    return sha256(this.pubkey).hex
  }

  get pubkey () : string {
    return this._pubkey.hex
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

  ecdh (pubkey : Bytes) : Buff {
    return get_shared_key(this._seckey, pubkey)
  }

  async export_aes (secret : string) {
    // Export as a password-encrypted payload.
    const encoded = Buff.str(secret)
    const payload = await encrypt_seed(this._seed, encoded)
    return payload.hex
  }
  
  async export_note (pubkey : string) {
    const shared  = this.ecdh(pubkey).slice(1)
    const seed    = this._seed
    const vector  = Buff.random(16)
    const payload = await encrypt(shared, seed, vector, 'AES-CBC')
    const content = payload.b64url + '?iv=' + vector.b64url
    const params  = [ [ 'kind', 4 ], [ 'p', pubkey ], [ 'stamp', now() ] ]
    const proof   = await this.notarize(content, params)
    return create_event(content, proof)
  }

  gen_nonce (
    message  : Bytes,
    options ?: SignOptions
  ) : Buff {
    const sn = this._gen_nonce(options)(message)
    return get_pubkey(sn, true)
  }

  hmac (message : Bytes) : Buff {
    return hmac512(this._seckey, message)
  }

  musign (
    context  : MusigContext,
    auxdata  : Bytes,
    options ?: SignOptions
  ) : Buff {
    return this._musign(options)(context, auxdata)
  }

  async notarize (
    content : string,
    params  : Params
  ) {
    return create_proof(content, this.pubkey, this._sign(), params)
  }

  sign (
    message  : Bytes,
    options ?: SignOptions
  ) : string {
    return this._sign(options)(message)
  }

}

import { Buff, Bytes }    from '@cmdcode/buff'
import { get_shared_key } from '@cmdcode/crypto-tools/ecdh'
import { Network }        from '@scrow/tapscript'
import { Wallet }         from './wallet.js'

import {
  hmac256,
  hmac512
} from '@cmdcode/crypto-tools/hash'

import {
  get_pubkey,
  get_seckey
} from '@cmdcode/crypto-tools/keys'

import {
  MusigContext,
  musign
} from '@cmdcode/musig2'

import {
  gen_nonce,
  sign_msg
} from '@cmdcode/crypto-tools/signer'

import { KeyConfig, SignOptions } from '../types.js'

import * as assert from '../assert.js'

const DEFAULT_IDGEN = () => Buff.random(32)
const MSG_MIN_VALUE = 0xFFn ** 24n

export class KeyPair {

  readonly _id     : Buff
  readonly _pubkey : Buff
  readonly _seckey : Buff

  constructor (config : KeyConfig) {
    const { seed, id } = config
    // Use the secret as the key.
    this._seckey = get_seckey(seed)
    // Compute the pubkey from the seckey.
    this._pubkey = get_pubkey(this._seckey, true)
    // Set the hash identifier for the keypair.
    this._id = (id !== undefined)
      ? Buff.bytes(id)
      : this.hmac('256', this.pubkey)
  }

  get is_root () {
    const root_id = this.hmac('256', this.pubkey)
    return root_id.hex === this.id
  }

  get id () {
    return this._id.hex
  }

  get pubkey () {
    return this._pubkey.hex
  }

  ecdh (pubkey : Bytes) {
    return get_shared_key(this._seckey, pubkey)
  }

  hmac (size : '256' | '512', ...bytes : Bytes[]) {
    return (size === '512')
      ? hmac512(this._seckey, ...bytes)
      : hmac256(this._seckey, ...bytes)
  }

  wallet (network ?: Network) {
    return Wallet.create(this._seckey, network)
  }
}

export class Signer extends KeyPair {

  static generate (config : Partial<KeyConfig>) {
    const seed = Buff.random(32)
    return new Signer({ ...config, seed })
  }

  readonly _gen_id : () => Bytes

  constructor (config : KeyConfig) {
    super(config)
    this._gen_id = config.id_gen ?? DEFAULT_IDGEN
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

  has_id (id : Bytes, pubkey : Bytes) {
    const kp = this.get_id(id)
    return kp.pubkey === Buff.bytes(pubkey).hex
  }

  gen_id () {
    const id = this._gen_id()
    return this.get_id(id)
  }

  get_id (id : Bytes) {
    const seed = this.hmac('256', this.pubkey, id)
    return new Signer({ seed, id })
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

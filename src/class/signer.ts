import { Buff, Bytes }  from '@cmdcode/buff'
import { ecdh }         from '@cmdcode/crypto-tools/ecdh'
import { create_token } from '../lib/token.js'

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

import {
  claim_credential,
  gen_credential
} from '../lib/cred.js'

import {
  CredentialData,
  KeyConfig,
  SignOptions,
  TokenOptions
} from '../types.js'

import * as assert from '../assert.js'

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
    this._pubkey = get_pubkey(this._seckey)
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

  get parity () {
    return this._pubkey.slice(0, 1).hex
  }

  get pubkey () {
    return this._pubkey.slice(1).hex
  }

  ecdh (pubkey : Bytes, xonly = false) {
    return ecdh(this._seckey, pubkey, xonly)
  }

  hmac (size : '256' | '512', ...bytes : Bytes[]) {
    return (size === '512')
      ? hmac512(this._seckey, ...bytes)
      : hmac256(this._seckey, ...bytes)
  }

  toJSON () {
    const { id, pubkey } = this
    return { id, pubkey }
  }

  toString() {
    return JSON.stringify(this.toJSON(), null, 2)
  }
}

export class Signer extends KeyPair {

  static claim (
    cred : CredentialData,
    xprv : string
  ) {
    const seed = claim_credential(cred, xprv)
    return new Signer({ seed, id : cred.id })
  }

  static generate (config : KeyConfig) {
    const seed = Buff.random(32)
    return new Signer({ ...config, seed })
  }

  constructor (config : KeyConfig) {
    // Initialize the keypair object.
    super(config)
  }

  _gen_cred () {
    return (index : number, xpub : string) => {
      return gen_credential(index, this._seckey, xpub)
    }
  }

  _gen_nonce (opt ?: SignOptions) {
    const config = { aux: null, ...opt }
    return (msg : Bytes) : Buff => {
      return gen_nonce(msg, this._seckey, config)
    }
  }

  _gen_token (options ?: TokenOptions) {
    return (content : string) => {
      return create_token(content, this._seckey, options)
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

  gen_cred (idx : number, xpub : string) : CredentialData {
    return this._gen_cred()(idx, xpub)
  }

  gen_nonce (
    message  : Bytes,
    options ?: SignOptions
  ) : Buff {
    const sn = this._gen_nonce(options)(message)
    return get_pubkey(sn, true)
  }

  gen_token (
    content  : string,
    options ?: TokenOptions
  ) {
    const token = this._gen_token(options)(content)
    return token.str
  }

  get_id (id : Bytes) {
    const seed = this.hmac('256', this.pubkey, id)
    return new Signer({ seed, id })
  }

  has_id (id : Bytes, pubkey : Bytes) {
    const child = this.get_id(id)
    return child.pubkey === Buff.bytes(pubkey).hex
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

  toJSON () {
    const { id, pubkey } = this
    return { id, pubkey }
  }

  toString() {
    return JSON.stringify(this.toJSON(), null, 2)
  }
}

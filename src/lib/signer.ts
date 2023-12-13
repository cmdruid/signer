import { Buff, Bytes }    from '@cmdcode/buff'
import { hmac512 }        from '@cmdcode/crypto-tools/hash'
import { get_shared_key } from '@cmdcode/crypto-tools/ecdh'
import { now }            from '../util.js'
import { MasterWallet }   from './wallet.js'

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

import {
  create_event,
  create_proof
} from './proof.js'

import {
  decrypt_data,
  encrypt_content,
  encrypt_data,
  get_ref,
  import_key,
  parse_passkey
} from './util.js'

import {
  Params,
  SignOptions
} from '../types.js'

import * as assert from '../assert.js'
import * as util   from './util.js'

const MSG_MIN_VALUE = 0xFFn ** 24n

export class Signer {

  static generate () {
    const seed = Buff.random(32)
    return new Signer(seed)
  }

  static async from_passkey (
    keypass : Bytes,
    secret  : string
  ) {
    const parsed  = parse_passkey(keypass)
    const encoded = Buff.str(secret)
    assert.ok(parsed.payload !== null, 'there is no encrypted data present')
    const seckey  = await decrypt_data(parsed.payload, encoded)
    const signer  = new Signer(seckey, parsed.id, parsed.ref)
    assert.ok(signer.pubkey === parsed.pubkey, 'imported signer does not match pubkey')
    return signer
  }

  static from_words (
    words : string | string[],
    pass ?: string
  ) {
    const seed = import_key.from_words(words, pass)
    return new Signer(seed)
  }

  static util = util

  readonly _id     : Buff
  readonly _pubkey : Buff
  readonly _ref    : Buff
  readonly _seckey : Buff

  constructor (
    seckey : Bytes,
    id    ?: Bytes,
    ref   ?: Bytes
  ) {
    this._seckey = Buff.bytes(seckey)
    this._pubkey = get_pubkey(this._seckey, true)
    this._id     = (id !== undefined)
      ? Buff.bytes(id)
      : Buff.random(32)
    this._ref    = (ref !== undefined)
      ? Buff.bytes(ref)
      : Buff.random(32)
  }

  get id () : string {
    return this._id.hex
  }

  get passkey () : string {
    return Buff.join([ this.pubkey, this.id, this.ref ]).hex
  }

  get pubkey () : string {
    return this._pubkey.hex
  }

  get ref () : string {
    return this._ref.hex
  }

  get wallet () : MasterWallet {
    return MasterWallet.from_seed(this._seckey)
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

  derive (id ?: Bytes) {
    if (id === undefined) {
      id = Buff.random(32)
    }
    const seed   = this.hmac(id, this._pubkey)
    const seckey = get_seckey(seed)
    const ref    = get_ref(this._pubkey, seckey)
    return new Signer(seckey, id, ref)
  }

  ecdh (pubkey : Bytes) : Buff {
    return get_shared_key(this._seckey, pubkey)
  }

  async export_data (secret : string) {
    const encoded = Buff.str(secret)
    const payload = await encrypt_data(this._seckey, encoded)
    return Buff.join([ this.passkey, payload ]).hex
  }


  async export_note (pubkey : string) {
    if (pubkey.length === 64) {
      pubkey = '02' + pubkey
    }
    const secret  = this.ecdh(pubkey).slice(1)
    const content = JSON.stringify({
      id     : this.id,
      ref    : this.ref,
      seckey : this._seckey.hex
    })
    const payload = await encrypt_content(content, secret)
    const params  = [ [ 'kind', 4 ], [ 'p', pubkey ], [ 'stamp', now() ] ]
    const proof   = await this.notarize(payload, params)
    return create_event(payload, proof)
  }

  gen_nonce (
    message  : Bytes,
    options ?: SignOptions
  ) : Buff {
    const sn = this._gen_nonce(options)(message)
    return get_pubkey(sn, true)
  }

  hmac (...messages : Bytes[]) : Buff {
    return hmac512(this._seckey, ...messages)
  }

  is_child (passkey : string) {
    const parsed = parse_passkey(passkey)
    const child  = this.derive(parsed.id)
    return child.pubkey === parsed.pubkey
  }

  is_parent (pubkey : Bytes) {
    const ref = get_ref(pubkey, this._seckey)
    return ref.hex === this.ref
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

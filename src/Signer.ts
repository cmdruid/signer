import { Buff, Bytes }       from '@cmdcode/buff-utils'
import { ecc, digest, ecdh } from '@cmdcode/crypto-utils'

import {
  MusigContext,
  MusigOptions,
  sig    as ms,
  verify as mv
} from '@cmdcode/musig2'

import {
  signer_config,
  SignerConfig,
  SignerOptions
} from './config.js'

import * as assert from './assert.js'

export class Signer {
  static generate (
    opt ?: SignerOptions
  ) : Signer {
    const sec = ecc.gen_seckey()
    return new Signer(sec, opt)
  }

  static verify = {
    sig   : ecc.verify,
    psig  : mv.psig,
    musig : mv.musig,
    cosig : mv.sig
  }

  readonly _pubkey : Buff
  readonly _seckey : Buff
  readonly _config : SignerConfig

  constructor (
    secret   : Bytes,
    options ?: SignerOptions
  ) {
    // Apply defaults to config.
    const opt = signer_config(options)
    // If path is specified:
    if (typeof opt.path === 'string') {
      // Unpack path config.
      const { path, chain_code } = opt
      // Derive new key and code from path.
      const [ sec, code ] = ecc.derive(path, secret, chain_code, true)
      // Apply new key as secret.
      secret = sec
      // Apply new chain code to config.
      opt.chain_code = code.hex
    }

    this._seckey = ecc.get_seckey(secret)
    this._pubkey = ecc.get_pubkey(this._seckey)
    this._config = opt
  }

  _gen_nonce (
    message : Bytes,
    aux    ?: Bytes
  ) : [ sec_nonce : Bytes, pub_nonce : Bytes ] {
    const min  = this._config.msg_min
    const msg  = Buff.bytes(message)
      let seed = this._seckey
    assert.size(msg, 32)
    assert.min_value(msg, min)
    if (aux !== undefined) {
      const a = digest('BIP0340/aux', aux)
      seed = Buff.big(seed.big ^ a.big)
    }
    const n = [ seed, this._pubkey, Buff.bytes(message) ]
    const sec_nonce = digest('BIP0340/nonce', ...n)
    return [ sec_nonce, ecc.get_pubkey(sec_nonce) ]
  }

  async derive (
    path : string,
    chain_code ?: string
  ) : Promise<Signer> {
    const config = { ...this._config, path, chain_code }
    return new Signer(this._seckey, config)
  }

  async getPublicKey () : Promise<string> {
    return this._pubkey.hex
  }

  async getSharedCode (
    pubkey  : Bytes,
    message : Bytes,
    tag    ?: string
  ) : Promise<string> {
    const opt  = { aux: message, tag }
    const code = ecdh.get_shared_code(this._seckey, pubkey, opt)
    return code.hex
  }

  async sign (message : Bytes) : Promise<string> {
    const min = this._config.msg_min
    const msg = Buff.bytes(message)
    assert.size(msg, 32)
    assert.min_value(msg, min)
    return ecc.sign(message, this._seckey, this._config).hex
  }

  async cosign (
    message   : Bytes,
    pub_key   : Bytes,
    pub_nonce : Bytes,
    sec_nonce : Bytes,
    tweaks    : Bytes[] = []
  ) : Promise<[ string, MusigContext ]> {
    const [ psig, ctx ] = ms.cosign(
      message,
      pub_key,
      pub_nonce,
      this._seckey,
      sec_nonce,
      { tweaks }
    )
    return [ psig.hex, ctx ]
  }

  async musign (
    message    : Bytes,
    pub_keys   : Bytes[],
    pub_nonces : Bytes[],
    sec_nonce  : Bytes,
    options   ?: MusigOptions
  ) : Promise<[ string, MusigContext ]> {
    const [ psig, ctx ] = ms.musign(
      message,
      pub_keys,
      pub_nonces,
      this._seckey,
      sec_nonce,
      options
    )
    return [ psig.hex, ctx ]
  }

  async recover (
    signature : Bytes,
    message   : Bytes,
    pubkey    : Bytes,
    options  ?: SignerConfig
  ) : Promise<Signer> {
    if (options === undefined) {
      options = this._config
    }
    const sec = ecc.recover(
      signature,
      message,
      pubkey,
      this._seckey
    )
    return new Signer(sec, options)
  }
}

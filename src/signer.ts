import { Buff, Bytes }    from '@cmdcode/buff'
import { parse_tx }       from '@scrow/tapscript/tx'
import { hmac512 }        from '@cmdcode/crypto-tools/hash'
import { derive_key }     from '@cmdcode/crypto-tools/hd'
import { get_shared_key } from '@cmdcode/crypto-tools/ecdh'

import {
  MusigContext,
  get_ctx,
  get_key_ctx,
  get_nonce_ctx,
  keys,
  musign,
  verify_musig,
  verify_psig
} from '@cmdcode/musig2'

import {
  SigHashOptions,
  TapConfig,
  TxBytes,
  TxData
} from '@scrow/tapscript'

import {
  hash_tx,
  sign_tx,
  verify_tx
} from '@scrow/tapscript/sighash'

import {
  parse_cblock,
  tap_pubkey,
  verify_cblock
} from '@scrow/tapscript/tapkey'

import {
  gen_seckey,
  get_seckey,
  get_pubkey
} from '@cmdcode/crypto-tools/keys'

import {
  create_proof,
  parse_proof,
  validate_proof,
  verify_proof
} from '@cmdcode/crypto-tools/proof'

import {
  gen_nonce,
  sign_msg,
  verify_sig
} from '@cmdcode/crypto-tools/signer'

import {
  SignerConfig,
  SignerOptions
} from './types.js'

import * as assert from './assert.js'

const MSG_MIN_VALUE = 0xFFn ** 24n

export class Signer {
  static generate (
    config ?: SignerConfig
  ) : Signer {
    const sec = gen_seckey()
    return new Signer(sec, config)
  }

  static musig = {
    verify_psig,
    verify_musig,
    get_ctx,
    get_key_ctx,
    get_nonce_ctx
  }

  static proof = {
    parse    : parse_proof,
    validate : validate_proof,
    verify   : verify_proof
  }

  static sig = {
    verify: verify_sig
  }

  static tap = {
    parse_cblock,
    verify_cblock
  }

  static tx = {
    hash_tx,
    parse_tx,
    verify_tx
  }

  readonly _pubkey  : Buff
  readonly _seckey  : Buff
  readonly _chain ?: Buff
  readonly _config  : SignerConfig

  constructor (
    secret : Bytes,
    config : SignerConfig = {}
  ) {
    const { hd_path, hd_code } = config
    if (typeof hd_path === 'string') {
      // Derive new key and code from path.
      const { seckey, code } = derive_key(
        hd_path, secret, hd_code, true
      )
      // Assert that the secret key exists.
      assert.exists(seckey)
      // Apply new key as secret.
      secret = seckey
      // Apply new chain code to config.
      this._chain = code
    }

    this._seckey = get_seckey(secret)
    this._pubkey = get_pubkey(this._seckey, true)
    this._config = config
  }

  get pubkey () : Buff {
    return this._pubkey
  }

  _create_proof (opt ?: SignerOptions) {
    const config = { ...this._config, ...opt }
    return <T> (
      content : T,
      params  : string[][] = []
    ) : string => {
      return create_proof(this._seckey, content, params, config)
    }
  }

  _gen_nonce (opt ?: SignerOptions) {
    const config = { aux: null, ...this._config, ...opt }
    return (msg : Bytes) : Buff => {
      return gen_nonce(msg, this._seckey, config)
    }
  }

  _gen_session_nonce (
    group_pub : Bytes,
    aux_data  : Bytes,
    options  ?: SignerOptions
  ) : Buff {
    const img = Buff.join([ group_pub, aux_data ])
    const sn1 = this._gen_nonce(options)(img)
    const sn2 = this._gen_nonce(options)(img.digest)
    return Buff.join([ sn1, sn2 ])
  }

  _musign (opt ?: SignerOptions) {
    const config = { ...this._config, ...opt }
    return (
      context  : MusigContext,
      aux_data : Bytes
    ) : Buff => {
      const { group_pubkey } = context
      const sn = this._gen_session_nonce(group_pubkey, aux_data, config)
      return musign(context, this._seckey, sn)
    }
  }

  _sign_msg (opt ?: SignerOptions) {
    const config = { ...this._config, ...opt }
    return (msg : Bytes) : Buff => {
      assert.size(msg, 32)
      assert.min_value(msg, MSG_MIN_VALUE)
      return sign_msg(msg, this._seckey, config)
    }
  }

  _sign_tx (opt ?: SignerOptions) {
    const options = { ...this._config, ...opt }
    return (
      txdata  : TxBytes | TxData,
      config ?: SigHashOptions
    ) : Buff => {
      return sign_tx(this._seckey, txdata, config, options)
    }
  }

  derive (path : string) : Signer {
    const config = { ...this._config, path }
    return new Signer(this._seckey, config)
  }

  ecdh (pubkey : Bytes) : Buff {
    return get_shared_key(this._seckey, pubkey)
  }

  gen_nonce (
    message  : Bytes,
    options ?: SignerOptions
  ) : Buff {
    const sn = this._gen_nonce(options)(message)
    return get_pubkey(sn, true)
  }

  gen_session_nonce (
    group_pub : Bytes,
    aux_data  : Bytes,
    options  ?: SignerOptions
  ) : Buff {
    const sn = this._gen_session_nonce(group_pub, aux_data, options)
    return keys.get_pub_nonce(sn)
  }

  get_tapkey (config : TapConfig) {
    return tap_pubkey(this.pubkey, config)
  }

  hmac (message : Bytes) : Buff {
    return hmac512(this._seckey, message)
  }

  musign (
    context  : MusigContext,
    aux_data : Bytes,
    options ?: SignerOptions
  ) : Buff {
    return this._musign(options)(context, aux_data)
  }

  sign_msg (
    message  : Bytes,
    options ?: SignerOptions
  ) : Buff {
    return this._sign_msg(options)(message)
  }

  sign_note <T> (
    content  : T,
    params  ?: string[][],
    options ?: SignerOptions
  ) {
    return this._create_proof(options)(content, params)
  }

  // sign_req (
  //   url  : string,
  //   body : string
  // ) : Buff {
  //   return this._create_proof(options)(url, body)
  // }

  sign_tx (
    txdata   : TxBytes | TxData,
    config  ?: SigHashOptions,
    options ?: SignerOptions
  ) : Buff {
    return this._sign_tx(options)(txdata, config)
  }
}

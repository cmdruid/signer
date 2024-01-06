import { Buff, Bytes }    from '@cmdcode/buff'
import { get_shared_key } from '@cmdcode/crypto-tools/ecdh'
import { Network }        from '@scrow/tapscript'
import { MasterWallet }   from './wallet.js'

import {
  hmac256,
  hmac512
} from '@cmdcode/crypto-tools/hash'

import {
  get_pubkey,
  get_seckey
} from '@cmdcode/crypto-tools/keys'

export class KeyPair {

  readonly _id     : Buff
  readonly _pubkey : Buff
  readonly _seckey : Buff

  constructor (
    seckey : Bytes,
    id    ?: Bytes
  ) {
    // Use the secret as the key.
    this._seckey = get_seckey(seckey)
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

  derive (id : Bytes) {
    const seckey = this.hmac('256', this.pubkey, id)
    return new KeyPair(seckey, id)
  }

  ecdh (pubkey : Bytes) {
    return get_shared_key(this._seckey, pubkey)
  }

  hmac (size : '256' | '512', ...bytes : Bytes[]) {
    return (size === '512')
      ? hmac512(this._seckey, ...bytes)
      : hmac256(this._seckey, ...bytes)
  }

  is_child (id : Bytes, pubkey : Bytes) {
    const kp = this.derive(id)
    return kp.pubkey === Buff.bytes(pubkey).hex
  }

  wallet (network ?: Network) {
    return MasterWallet.create(this._seckey, network)
  }
}
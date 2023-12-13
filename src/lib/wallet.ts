import { Buff, Bytes } from '@cmdcode/buff'
import { HDKey }       from '@scure/bip32'
import { Network }     from '@scrow/tapscript'
import { import_key }  from './util.js'

import {
  P2WPKH,
  parse_addr
} from '@scrow/tapscript/address'

import * as assert from '../assert.js'

const DEFAULT_PATH = "m/84'/0'/0'/0"

export class ExtendedKey {

  readonly _hd : HDKey

  constructor (hd : HDKey) {
    // Assert that we have a proper HDKey instance.
    if (!(hd instanceof HDKey)) {
      throw new Error('Invalid HD Key!')
    }

    // If HDKey contains private data, remove it.
    if (hd.privateKey !== null) {
      hd = hd.wipePrivateData()
    }

    this._hd = hd
  }

  get hd () : HDKey {
    return this._hd
  }

  get index () : number {
    return this.hd.index
  }

  get pubkey () : string {
    assert.exists(this.hd.publicKey)
    return Buff.raw(this.hd.publicKey).hex
  }

  get xpub () : string {
    return this.hd.publicExtendedKey
  }

  address (network : Network = 'main') {
    return P2WPKH.create(this.pubkey, network)
  }
}

export class Wallet extends ExtendedKey {

  static from_xpub (xpub : string) {
    const hdkey = HDKey.fromExtendedKey(xpub)
    return new Wallet(hdkey)
  }

  _idx : number

  constructor (
    hdkey : HDKey,
    start_idx = 0
  ) {
    super(hdkey)
    this._idx = start_idx
  }

  get current () {
    const key = this.hd.deriveChild(this.idx)
    return new ExtendedKey(key)
  }

  get idx () {
    return this._idx
  }

  _next () {
    this._idx = this.idx + 1
  }

  get_address (index : number, network ?: Network) {
    const key = this.get_pubkey(index)
    return key.address(network)
  }

  get_pubkey (index : number) {
    const hd = this.hd.deriveChild(index)
    return new ExtendedKey(hd)
  }

  has_address (address : string, limit = 1000) {
    const addr = parse_addr(address)
    for (let i = 0; i < limit; i++) {
      const curr = this.hd.deriveChild(i)
      if (addr.type === 'p2pkh' || addr.type === 'p2w-pkh') {
        if (curr.pubKeyHash !== undefined) {
          const hash = Buff.raw(curr.pubKeyHash)
          if (hash.hex === addr.key) return true
        }
      } else if (addr.type === 'p2tr') {
        if (curr.publicKey !== null) {
          const pub = Buff.raw(curr.publicKey)
          if (pub.hex === addr.key) return true
        }
      } else {
        throw new Error('unsupported address type: ' + addr.type)
      }
    }
    return false
  }

  has_pubkey (pubkey : string, limit = 1000) {
    for (let i = 0; i < limit; i++) {
      const curr = this.hd.deriveChild(i)
      if (curr.publicKey !== null) {
        const pub = Buff.raw(curr.publicKey)
        if (pub.hex === pubkey) return true
      }
    }
    return false
  }

  new_address (network : Network = 'main') {
    this._next()
    return this.current.address(network)
  }

  new_pubkey (network : Network = 'main') {
    this._next()
    return this.current.address(network)
  }

}

export class MasterWallet extends ExtendedKey {
  
  static from_seed (seed : Bytes) {
    const uint8 = Buff.bytes(seed).raw
    const mstr  = HDKey.fromMasterSeed(uint8)
    const path  = DEFAULT_PATH
    const hdkey = mstr.derive(path)
    return new MasterWallet(hdkey)
  }

  static from_words (words : string | string[]) {
    const seed = import_key.from_words(words)
    return MasterWallet.from_seed(seed)
  }

  static from_xpub (xpub : string) {
    const hdkey = HDKey.fromExtendedKey(xpub)
    return new MasterWallet(hdkey)
  }

  constructor (hdkey : HDKey) {
    super(hdkey)
  }

  has_account (extkey : string | HDKey) {
    if (typeof extkey === 'string') {
      extkey = HDKey.fromExtendedKey(extkey)
    }
    const hda = new ExtendedKey(extkey)
    const hdb = new ExtendedKey(this.hd.deriveChild(hda.index))
    return hda.pubkey === hdb.pubkey
  }

  get_account (acct : number, index ?: number) {
    const hd_acct = this.hd.deriveChild(acct)
    return new Wallet(hd_acct, index)
  }

  new_account () {
    const idx = Buff.random(4).num & 0x7FFFFFFF
    return this.get_account(idx)
  }

}

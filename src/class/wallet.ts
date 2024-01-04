import { Buff, Bytes }   from '@cmdcode/buff'
import { HDKey }         from '@scure/bip32'
import { Network }       from '@scrow/tapscript'
import { AddressConfig } from '../types.js'

import {
  P2WPKH,
  parse_addr
} from '@scrow/tapscript/address'

import * as assert from '../assert.js'

const DEFAULT_PATH = "m/84'/0'/0'"

const DEFAULT_ADDR_CONFIG = {
  format  : 'p2pkh',
  network : 'main' as Network
}

export class ExtendedKey {

  readonly _hd  : HDKey

  constructor (extkey : string | HDKey) {
    // Assert that we have a proper HDKey instance.
    if (typeof extkey === 'string') {
      extkey = HDKey.fromExtendedKey(extkey)
    }

    // If HDKey contains private data, remove it.
    if (extkey.privateKey !== null) {
      extkey = extkey.wipePrivateData()
    }

    this._hd  = extkey
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

  address (options ?: Partial<AddressConfig>) : string {
    const conf = { ...DEFAULT_ADDR_CONFIG, ...options }
    if (conf.format === 'p2wpkh') {
      return P2WPKH.create(this.pubkey, conf.network)
    }
    throw new Error('unrecognized address format: ' + conf.format)
  }
}

export class Wallet extends ExtendedKey {

  _cache : string[]
  _idx   : number

  constructor (
    extkey    : HDKey | string,
    start_idx : number = 0
  ) {
    super(extkey)
    this._cache = []
    this._idx   = start_idx
  }

  get current () {
    return this.get_extkey(this.idx)
  }

  get idx () {
    return this._idx
  }

  _cache_addr (addr : string) {
    if (!this._cache.includes(addr)) {
      this._cache.push(addr)
    }
  }

  get_address (
    index    : number,
    options ?: Partial<AddressConfig>
  ) {
    const type = options?.type ?? 0
    const key  = this.get_extkey(index, type)
    const addr = key.address(options)
    this._cache_addr(addr)
    return addr
  }

  get_extkey (index : number, type = 0) {
    const hd = this.hd.deriveChild(type).deriveChild(index)
    return new ExtendedKey(hd)
  }

  has_address (
    address : string,
    type  = 0,
    limit = 100
  ) {
    if (this._cache.includes(address)) {
      return true
    } else {
      const { network, type: format } = parse_addr(address)
      const opt = { format, network, type }
      for (let i = 0; i <= limit; i++) {
        const curr = this.get_address(i, opt)
        if (curr === address) {
          return true
        }
      }
      return false
    }
  }

  new_address (options ?: Partial<AddressConfig>) : string {
    this._idx  = this.idx + 1
    const addr = this.get_address(this.idx, options)
    this._cache_addr(addr)
    return addr
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

  constructor (extkey  : HDKey | string) {
    super(extkey)
  }

  get new_account () : Wallet {
    const acct = Buff.random(4).num
    return this.get_account(acct)
  }

  get_account (
    acct      : number,
    start_idx : number = 0
  ) {
    const hd = this.hd.deriveChild(acct & 0x7FFFFFFF)
    return new Wallet(hd, start_idx)
  }

  has_account (extkey : string | HDKey | ExtendedKey) {
    if (!(extkey instanceof ExtendedKey)) {
      extkey = new ExtendedKey(extkey)
    }
    const hd   = this.hd.deriveChild(extkey.index)
    const xkey = new ExtendedKey(hd)
    return extkey.pubkey === xkey.pubkey
  }

}

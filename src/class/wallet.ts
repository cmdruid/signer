import { Buff, Bytes }  from '@cmdcode/buff'
import { HDKey }        from '@scure/bip32'
import { Network }      from '@scrow/tapscript'
import { import_seed }  from '../lib/util.js'
import { WalletConfig } from '../types.js'

import {
  P2WPKH,
  parse_addr
} from '@scrow/tapscript/address'

import * as assert from '../assert.js'

const DEFAULT_PATH   = "m/84'/0'/0'/0"
const DEFAULT_CONFIG : WalletConfig = { network : 'main' }

export class ExtendedKey {

  readonly _hd  : HDKey
  readonly _opt : WalletConfig

  constructor (
    extkey  : string | HDKey,
    options : WalletConfig = {}
  ) {
    // Assert that we have a proper HDKey instance.
    if (typeof extkey === 'string') {
      extkey = HDKey.fromExtendedKey(extkey)
    }

    // If HDKey contains private data, remove it.
    if (extkey.privateKey !== null) {
      extkey = extkey.wipePrivateData()
    }

    this._hd  = extkey
    this._opt = { ...DEFAULT_CONFIG, ...options }
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

  get address () : string {
    return P2WPKH.create(this.pubkey, this._opt.network)
  }
}

export class Wallet extends ExtendedKey {

  _cache : string[]
  _idx   : number

  constructor (
    extkey  : HDKey | string,
    options : WalletConfig = {}
  ) {
    super(extkey, options)
    this._cache = []
    this._idx   = options.start_idx ?? 0
    this._register(this.current.address)
  }

  get current () {
    return this.get_extkey(this.idx)
  }

  get idx () {
    return this._idx
  }

  get new_address () : string {
    this._idx  = this.idx + 1
    const addr = this.current.address
    this._register(addr)
    return addr
  }

  _register (addr : string) {
    if (!this._cache.includes(addr)) {
      this._cache.push(addr)
    }
  }

  get_address (index : number) {
    const key  = this.get_extkey(index)
    const addr = key.address
    this._register(addr)
    return addr
  }

  get_extkey (index : number) {
    const hd = this.hd.deriveChild(index)
    return new ExtendedKey(hd)
  }

  has_address (address : string, limit = 100) {
    if (this._cache.includes(address)) {
      return true
    } else {
      const { network, type } = parse_addr(address)
      assert.is_p2pkh(type)
      assert.is_network(network, this._opt.network as string)
      for (let i = 0; i <= limit; i++) {
        const curr = this.get_address(i)
        if (curr === address) return true
      }
      return false
    }
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
    const seed = import_seed.from_words(words)
    return MasterWallet.from_seed(seed)
  }

  _net : Network

  constructor (
    extkey  : HDKey | string,
    network : Network = 'main'
  ) {
    super(extkey)
    this._net = network
  }

  get new_account () : Wallet {
    const acct = Buff.random(4).num
    return this.get_account(acct)
  }

  get_account (acct : number, start_idx ?: number) {
    const opt = { ...this._opt, start_idx }
    const hd = this.hd.deriveChild(acct & 0x7FFFFFFF)
    return new Wallet(hd, opt)
  }

  has_account (extkey : string | HDKey | ExtendedKey) {
    if (!(extkey instanceof ExtendedKey)) {
      extkey = new ExtendedKey(extkey)
    }
    const hd = new ExtendedKey(this.hd.deriveChild(extkey.index))
    return extkey.pubkey === hd.pubkey
  }

}

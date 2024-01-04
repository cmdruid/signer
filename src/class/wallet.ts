import { Buff, Bytes }   from '@cmdcode/buff'
import { HDKey }         from '@scure/bip32'
import { Network }       from '@scrow/tapscript'
import { AddressConfig } from '../types.js'

import {
  P2PKH,
  P2TR,
  P2WPKH,
  parse_addr
} from '@scrow/tapscript/address'

import * as assert from '../assert.js'

const PATHS = {
  main : "m/86'/0'/0'",
  test : "m/86'/1'/0'"
}

const VERSIONS = {
  main : { private : 0x0488ade4, public : 0x0488b21e },
  test : { private : 0x04358394, public : 0x043587cf }
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

  get version () {
    const curr_ver = this.hd.versions.public
    const main_ver = VERSIONS.main.public
    return (curr_ver === main_ver) ? 'main' : 'testnet'
  }

  get xpub () : string {
    return this.hd.publicExtendedKey
  }

  address (options ?: AddressConfig) : string {
    const format  = options?.format  ?? 'p2wpkh'
    const network = options?.network ?? this.version
    switch (format) {
      case 'p2wpkh':
        return P2WPKH.create(this.pubkey, network)
      case 'p2tr':
        return P2TR.create(this.pubkey, network)
      case 'p2pkh':
        return P2PKH.create(this.pubkey, network)
      default:
        throw new Error('invalid address format: ' + format)
    }
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

  get idx () {
    return this._idx
  }

  _cache_addr (addr : string) {
    if (!this._cache.includes(addr)) {
      this._cache.push(addr)
    }
  }

  derive_key (index : number) {
    const hd = this.hd.deriveChild(index)
    return new ExtendedKey(hd)
  }

  get_address (options ?: AddressConfig) {
    const idx  = options?.index ?? this.idx
    const key  = this.derive_key(idx)
    const addr = key.address(options)
    this._cache_addr(addr)
    return addr
  }

  has_address (
    address : string,
    limit = 100
  ) {
    if (this._cache.includes(address)) {
      return true
    } else {
      const { network, type: format } = parse_addr(address)
      const opt = { format, network, index : 0 }
      for (let i = 0; i <= limit; i++) {
        const curr = this.get_address(opt)
        if (curr === address) {
          return true
        } else {
          opt.index += 1
        }
      }
      return false
    }
  }

  new_address (options ?: AddressConfig) : string {
    const index = this.idx + 1
    const addr  = this.get_address({ ...options, index })
    this._idx   = index
    return addr
  }
}

export class MasterWallet extends ExtendedKey {

  static create (seed : Bytes, network : Network = 'main') {
    const ver   = (network === 'main') ? VERSIONS.main : VERSIONS.test
    const path  = (network === 'main') ? PATHS.main : PATHS.test
    const uint8 = Buff.bytes(seed).raw
    const mstr  = HDKey.fromMasterSeed(uint8, ver)
    const hdkey = mstr.derive(path)
    return new MasterWallet(hdkey)
  }

  static generate (network : Network = 'main') {
    const seed = Buff.random(64)
    return MasterWallet.create(seed, network)
  }

  constructor (extkey : HDKey | string) {
    super(extkey)
  }

  get new_account () : Wallet {
    const acct = Buff.random(4).num
    return this.get_account(acct)
  }

  get_account (
    account_id : number,
    start_idx  : number = 0
  ) {
    const hd = this.hd.deriveChild(account_id & 0x7FFFFFFF)
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

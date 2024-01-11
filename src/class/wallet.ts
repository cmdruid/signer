import { Buff, Bytes }     from '@cmdcode/buff'
import { HDKey }           from '@scure/bip32'
import { Network }         from '@scrow/tapscript'
import { parse_extkey }    from '../lib/util.js'
import { AddressConfig, WalletConfig }   from '../types.js'
import { PATHS, VERSIONS } from '../const.js'

import {
  P2PKH,
  P2TR,
  P2WPKH,
  parse_addr
} from '@scrow/tapscript/address'

import * as assert from '../assert.js'

export class ExtendedKey {

  readonly _hd : HDKey

  constructor (extkey : string | HDKey) {
    // Assert that we have a proper HDKey instance.
    if (typeof extkey === 'string') {
      extkey = parse_extkey(extkey)
    }
    this._hd = extkey
  }

  get code () {
    assert.exists(this.hd.chainCode)
    return Buff.raw(this.hd.chainCode).hex
  }

  get depth () {
    return this.hd.depth
  }

  get fp () {
    return Buff.num(this.hd.fingerprint, 4).hex
  }

  get hd () : HDKey {
    return this._hd
  }

  get index () : number {
    return this.hd.index
  }

  get pfp () {
    return Buff.num(this.hd.parentFingerprint, 4).hex
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

  get xprv () : string | null {
    return (this._hd.privateKey !== null)
      ? this._hd.privateExtendedKey
      : null
  }

  get xpub () : string {
    return this.hd.publicExtendedKey
  }

  address (options ?: AddressConfig) : string {
    const format  = options?.format  ?? 'p2w-pkh'
    const network = options?.network ?? this.version
    switch (format) {
      case 'p2w-pkh':
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

  static create (config : WalletConfig) {
    let { seed, path, network = 'main', versions } = config
    if (path === undefined) {
      path = (network === 'main') ? PATHS.main : PATHS.test
    }
    if (versions === undefined) {
      versions = (network === 'main') ? VERSIONS.main : VERSIONS.test
    }
    const uint8 = Buff.bytes(seed).raw
    const mstr  = HDKey.fromMasterSeed(uint8, versions)
    const hdkey = mstr.derive(path)
    return new Wallet(hdkey)
  }

  static generate (network : Network = 'main') {
    const seed = Buff.random(64)
    return Wallet.create({ seed, network })
  }

  _addr : string[]
  _idx  : number

  constructor (
    extkey    : HDKey | string,
    start_idx : number = 0
  ) {
    super(extkey)
    this._addr = []
    this._idx  = start_idx
  }

  get idx () {
    return this._idx
  }

  get wiped () {
    const hd = this._hd.wipePrivateData()
    return new Wallet(hd)
  }

  _cache (addr : string) {
    if (!this._addr.includes(addr)) {
      this._addr.push(addr)
    }
  }

  _derive (index : number) {
    const hd = this.hd.deriveChild(index)
    return new ExtendedKey(hd)
  }

  get_account (
    acct_id   : Bytes,
    start_idx : number = 0
  ) {
    const idx = Buff.bytes(acct_id).slice(0, 4).num & 0x7FFFFFFF
    const hd  = this.hd.deriveChild(idx)
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

  get_address (options ?: AddressConfig) {
    const idx  = options?.index ?? this.idx
    const key  = this._derive(idx)
    const addr = key.address(options)
    this._cache(addr)
    return addr
  }

  has_address (
    address : string,
    limit = 100
  ) {
    if (this._addr.includes(address)) {
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

  toJSON () {
    const { code, depth, fp, index, pfp, pubkey, xpub } = this
    return { code, depth, fp, index, pfp, pubkey, xpub }
  }

  toString () {
    return this.xpub
  }
}

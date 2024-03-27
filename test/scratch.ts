import { Seed, Signer } from '@/index.js'
import { Buff } from '@cmdcode/buff'
import { hash160 } from '@cmdcode/crypto-tools/hash'
import { P2WPKH, parse_addr } from '@scrow/tapscript/address'
import { HDKey } from '@scure/bip32'
import assert from 'assert'

const addr_ctx = parse_addr('bc1qy5enkjplrwm4kaag4qgqjppsjy4k3a6fy7z879')

const secrets = [
  undefined,
  // 'Constitution',
  // 'Constitution Day',
  // 'Obelisk, 18 July. It has happened.',
  // 'Yes, let us meet there and then at 10 p.m.',
  // 'Obelisk, 18 July. It has happened. Yes, let us meet there and then at 10 p.m.',
  // 'matilda',
  // 'better life'
]

const paths = [
  "m/44'/0'/0'",
  "m/44'/0'/0'/0",
  "m/44'/0'/0'/0/0",
  "m/84'/0'/0'",
  "m/84'/0'/0'/0",
  "m/84'/0'/0'/0/0",
  "m/86'/0'/0'",
  "m/86'/0'/0'/0",
  "m/86'/0'/0'/0/0",
]

const words = [
  'violin',   // 730279 
  'toddler',  // 731044
  'alley',    // 731401
  'shoulder', // 732749
  'educate',  // 735662
  'rookie',   // 738302
  'below',    // 740246
  'punch',    // 741093
  'certain',  // 741728
  'cover',    // 743199
  'agree',    // 745005
  'coast',    // 746846
  'suggest',  // 747947
  'boring',   // 749781
  'tissue',   // 172848
  'good',     // 753813
  'sausage',  // 756756 -
  'cute',     // 759150
  'club',     // 759739
  'runway',   // 095098
  'pluck',    // 08/01/1991 // 763616 // 763838
  'satoshi',  // 764971
  'home'      // 09/01/2003 // 767401
]

console.log('book hash:', addr_ctx.key)

for (const secret of secrets) {
  const seed   = Seed.import.from_words(words, secret)
  const extkey = HDKey.fromMasterSeed(seed)
  const pubkey = extkey.publicKey
  assert.ok(pubkey !== null)
  const pkh    = hash160(pubkey).hex
  const addr   = P2WPKH.create(pubkey)

  const signer = new Signer({ seed })
  const dpub   = signer.pubkey
  const dpkh   = hash160(dpub).hex
  const daddr  = P2WPKH.create(signer._pubkey)

  console.log('master seed :', Buff.raw(seed).hex)
  console.log('master pkh  :',  pkh)
  console.log('master addr :', addr)
  console.log('direct pkh  :', dpkh)
  console.log('direct addr :', daddr)

  // if (addr_ctx.key === pkh) {
  //   throw new Error('we found it!')
  // }

  for (const path of paths) {
    const chd  = extkey.derive(path)
    const cpub = chd.publicKey
    assert.ok(cpub !== null)
    const cpkh   = hash160(cpub).hex
    const caddr  = P2WPKH.create(cpub)
    // const wallet = new Wallet(extkey)
    console.log('child path  :', path)
    console.log('child pkh   :', cpkh)
    console.log('child addr  :', caddr)

    if (addr_ctx.key === cpkh) {
      throw new Error('we found it!')
    }
  }
}

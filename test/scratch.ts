import assert from 'assert'

import { Seed, Signer, Wallet } from '../src/index.js'

const seed   = Seed.import.from_char('alice')
const idxgen = () => 0
const wallet = Wallet.create({ seed, network : 'regtest' })
const xpub   = wallet.xpub
const signer = new Signer({ seed, idxgen })
const cred   = signer.gen_cred(0, xpub)

console.log('cred:', cred)

assert.ok(wallet.xprv !== null)

console.log('claimable:', signer.has_id(cred.id, cred.pub))

const s2 = signer.get_id(cred.id)

console.log('signer:', s2.toJSON())
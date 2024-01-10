import assert from 'assert'

import { Cred, Seed, Signer, Wallet } from '../src/index.js'

const seed   = Seed.import.from_char('alice')
const idxgen = undefined // () => 0
const wallet = Wallet.create(seed)
const xpub   = wallet.xpub
const signer = new Signer({ seed, idxgen })
const cred   = signer.gen_cred()

console.log('cred:', cred)

assert.ok(wallet.xprv !== null)

console.log('claimable:', signer.has_id(cred.id, cred.pub))

const s2 = signer.get_cred(cred)

console.log('signer:', s2.toJSON())
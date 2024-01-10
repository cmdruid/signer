import assert from 'assert'

import { Cred, Signer, Wallet } from '../src/index.js'

const signer = Signer.generate()
const wallet = Wallet.generate()

const cred = signer.gen_cred(wallet.xpub)

console.log('cred:', cred)

assert.ok(wallet.xprv !== null)

console.log('claimable:', Cred.has_id(cred, signer.pubkey, wallet.xpub))

const recv = Cred.claim(cred, wallet.xprv)

console.log('recovered:', recv.hex)
import assert from 'assert'

import { Seed, Signer, Wallet } from '../src/index.js'
import { Buff } from '@cmdcode/buff'

const seed   = Seed.import.from_char('alice')
const idxgen = () => 0
const wallet = Wallet.create({ seed, network : 'regtest' })
const xpub   = wallet.xpub
const signer = new Signer({ seed, idxgen })

const backup = signer.backup(Buff.str('test'))

console.log('signer:', signer.pubkey)
console.log('backup:', backup.hex)
console.log('size:', backup.length)

const restored = Signer.restore(Buff.str('test'), backup)

console.log('restored:', restored.pubkey)

console.log('is restored:', signer.pubkey === restored.pubkey)

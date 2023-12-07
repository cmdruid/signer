import { Buff }       from '@cmdcode/buff'
import { Signer }     from '../src/index.js'
import { get_pubkey } from '@cmdcode/crypto-tools/keys'

const seed = Buff.str('alice').digest
const sec  = Buff.str('carol').digest

console.log('seed:', seed.hex)

const signer = new Signer(seed)

const payload = await signer.export_aes('bananas')

console.log('payload:', payload)

const signer_2 = await Signer.from_aes(payload, 'bananas')

console.log('decrypted:', signer_2._seed.hex)

const pub  = get_pubkey(sec)
const note = await signer.export_note(pub.hex)

console.log('note:', JSON.stringify(note, null, 2))

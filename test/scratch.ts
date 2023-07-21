import { Signer }   from '../src/index.js'
import * as Endorse from '../src/note.js'

import {
  getEventHash,
  verifySignature
} from 'nostr-tools'

const a_signer = Signer.generate()
const content  = JSON.stringify([ 'hello', 'world!' ])
const proof    = await a_signer.endorse(content, [['kind', 21000 ]])

const is_valid = Signer.verify.endorsement(content, proof)

const event = Endorse.convert_to_event(content, proof)
const hash  = getEventHash(event)
const is_valid_event = verifySignature(event)

console.log('content:', content)
console.log('proof:', proof)
console.log('event:', event)
console.log('hash:', hash)
console.log('is_valid:', is_valid)
console.log('is_valid_event:', is_valid_event)

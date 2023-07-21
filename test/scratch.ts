import { Buff } from '@cmdcode/buff-utils'
import { Parse, Signer, Verify } from '../src/index.js'

import * as Note from '../src/note.js'

import { verifySignature } from 'nostr-tools'

const a_signer = Signer.generate()
const payload  = { contract_id : Buff.random(32).hex, path : 'payout' }
const note     = await a_signer.notarize(payload)
const content  = JSON.stringify(payload)
const proof    = await a_signer.endorse(content, [['kind', 21000 ], ['expires', 1234 ]])

const note_valid  = Verify.note(note)
const proof_valid = Verify.proof(content, proof)

const note_event     = Note.convert_note_to_event(note)
const proof_event    = Note.convert_proof_to_event(content, proof)
const is_valid_note  = verifySignature(note_event)
const is_valid_event = verifySignature(proof_event)

console.log('payload:', Parse.note(note))
console.log('note:', note)
console.log('proof:', proof)
console.log('event:', proof_event)
console.log('is_note_valid:', note_valid)
console.log('is_proof_valid:', proof_valid)
console.log('is_valid_proof_event:', is_valid_event)
console.log('is_valid_note_event:', is_valid_note)

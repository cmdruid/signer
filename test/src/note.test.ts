import { Test } from 'tape'
import { Buff } from '@cmdcode/buff-utils'

import { Signer, Verify } from '../../src/index.js'

import * as Note from '../../src/note.js'

import { verifySignature } from 'nostr-tools'

const TEST_KIND = 21000

export default async function (t : Test) {
  // Generate a random signer.
  const a_signer = Signer.generate()
  // Generate a random payload.
  const payload  = { contract_id : Buff.random(32).hex, path : 'payout' }
  // We can also set a custom policy for the proof.
  const params = [ ['kind', TEST_KIND ], ['expires', 1234 ] ]
  // Notarize the payload using the signer.
  const note     = await a_signer.notarize(payload, params)
  // Before endorsing a note, stringify the payload.
  const content  = JSON.stringify(payload)
  // Endorse the stringified note and get a proof in return.
  const proof = await a_signer.endorse(content, params)
  // Notes can be converted to a nostr event.
  const note_event  = Note.convert_note_to_event(note)
  // Proofs can also be converted to a nostr event.
  const proof_event = Note.convert_proof_to_event(content, proof)
  // Verify the note proof is valid.
  const note_valid  = Verify.note(note)
  // Verify the endorsement proof is valid.
  const proof_valid = Verify.proof(content, proof)
  // Verify the note is a valid nostr event.
  const is_valid_note_event  = verifySignature(note_event)
  // Verify the proof is a valid nostr event.
  const is_valid_proof_event = verifySignature(proof_event)

  t.test('Testing notes and endorsements', t => {
    t.plan(6)
    t.true(note_valid, 'The note should be valid.')
    t.true(proof_valid, 'The endorsement proof should be valid.')
    t.true(is_valid_note_event, 'The note should be a valid nostr event.')
    t.true(is_valid_proof_event, 'The proof should be a valid nostr event.')
    t.equal(note_event.kind, TEST_KIND, 'The note should have the proper kind.')
    t.equal(proof_event.kind, TEST_KIND, 'The proof should have the proper kind.')
  })
}

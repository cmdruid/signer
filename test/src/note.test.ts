import { Test } from 'tape'
import { Buff } from '@cmdcode/buff-utils'

import { Signer, Verify } from '../../src/index.js'

import * as Note from '../../src/proof.js'

import { verifySignature } from 'nostr-tools'

const TEST_KIND = 21000

export default async function (t : Test) {
  // Generate a random signer.
  const a_signer = Signer.generate()
  // Generate a random payload.
  const payload  = { contract_id : Buff.random(32).hex, path : 'payout' }
  // We can also set a custom policy for the proof.
  const params = [ ['kind', TEST_KIND ], ['expires', 1234 ] ]
  // Endorse the stringified note and get a proof in return.
  const proof = await a_signer.endorse(payload, params)
  // Proofs can be converted to a nostr event.
  const proof_event = Note.convert_to_event(payload, proof)
  // Verify the endorsement proof is valid.
  const proof_valid = Verify.proof(payload, proof)
  // Verify the proof is a valid nostr event.
  const is_valid_proof_event = verifySignature(proof_event)

  t.test('Testing notes and endorsements', t => {
    t.plan(3)
    t.true(proof_valid, 'The endorsement proof should be valid.')
    t.true(is_valid_proof_event, 'The proof should be a valid nostr event.')
    t.equal(proof_event.kind, TEST_KIND, 'The proof should have the proper kind.')
  })
}

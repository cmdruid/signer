import { Buff } from '@cmdcode/buff-utils'
import { ecc }  from '@cmdcode/crypto-utils'

import {
  DataSigner,
  Endorsement
} from './types.js'

import * as assert from './assert.js'

export const now = () : number => {
  return Math.floor(Date.now() / 1000)
}

export function create_endorsement (
  signer  : DataSigner,
  pubkey  : string,
  content : string,
  policy  : string[][] = []
) : Endorsement {
  const stamp   = now(),
        image   = [ 0, pubkey, stamp, 20000, policy, content ],
        id      = Buff.json(image).digest.hex,
        sig     = signer(id)
    let hash    = Buff.str(content).digest.hex
  if (policy.length > 0) {
    const params = new URLSearchParams(policy).toString()
    hash = hash + '?' + params
  }
  return [ hash, pubkey, stamp, id, sig ]
}

export function verify_endorsement (
  content : string,
  proof   : Endorsement,
  throws  = false
) : boolean {
  // Unpack the proof.
  let [ hash, pubkey, stamp, id, sig ] = proof
  // Initialize a policy array.
  let policy : string[][] = []
  // If the link includes params:
  if (hash.includes('?')) {
    // Split link into hash and params.
    const [ origin, params ] = hash.split('?')
    // Update link and policy.
    policy = [ ...new URLSearchParams(params) ]
    hash   = origin
  }
  // Hash the content.
  const content_hash = Buff.str(content).digest.hex
  // If the digest does not equal our link
  if (content_hash !== hash) {
    assert.fail('Content hash does not match the link!', throws)
  }
  const image = [ 0, pubkey, stamp, 20000, policy, content ]
  const proof_hash = Buff.json(image).digest.hex
  if (proof_hash !== id) {
    assert.fail('Proof hash does not equal proof id!', throws)
  }
  if (!ecc.verify(sig, id, pubkey)) {
    assert.fail('Proof signature is invalid!', throws)
  }
  verify_policy(proof)
  return true
}

function verify_policy (
  proof : Endorsement
) : void {
  void proof
}

import { Buff } from '@cmdcode/buff-utils'
import { ecc }  from '@cmdcode/crypto-utils'
import { now }  from './utils.js'

import {
  DataSigner,
  Event,
  Endorsement,
  Literal,
  ProofData
} from './types.js'

import * as assert from './assert.js'
import * as util   from './utils.js'

const KIND_MAX     = 0xFFFFFFFF
const KIND_DEFAULT = 20000

export function endorse_data <T> (
  signer : DataSigner,
  pubkey : string,
  data   : T,
  params : Literal[][] = []
) : Endorsement {
  // Stringify data.
  const content = util.stringify(data)
  // Convert all param values into strings.
  const strings = params.map(e => e.map(f => String(f)))
  // Get kind value from params, if present.
  const kind    = get_kind(strings, KIND_DEFAULT)
  // Get the current timestamp.
  const stamp   = now()
  // Build the pre-image that we will be hashing.
  const image   = [ 0, pubkey, stamp, kind, strings, content ]
  // Compute the hash id from the image.
  const id      = Buff.json(image).digest.hex
  // Compute a signature for the given id.
  const sig     = signer(id)
  // Create a reference hash from the content string.
  const ref     = compute_ref(content, strings)
  // Return proof of endorsement in array.
  return [ ref, pubkey, id, sig, stamp ]
}

export function verify_proof <T> (
  data   : T,
  proof  : Endorsement,
  throws = false
) : boolean {
  // Stringify data.
  const content = util.stringify(data)
  // Unpack the proof.
  const { ref, pubkey, id, sig, stamp } = parse_proof(proof)
  // Parse the hash and params.
  const [ hash, params ] = parse_ref(ref)
  // Get the kind value from params, if present.
  const kind = get_kind(params, KIND_DEFAULT)
  // Hash the content.
  const content_hash = Buff.str(content).digest.hex
  // Check if the hash does not match our link.
  if (content_hash !== hash) {
    assert.fail('Content hash does not match reference hash!', throws)
  }
  // Assemble the pre-image for the hashing function.
  const image = [ 0, pubkey, stamp, kind, params, content ]
  // Stringify and hash the preimage.
  const proof_hash = Buff.json(image).digest.hex
  // Check if the hash does not match our id.
  if (proof_hash !== id) {
    assert.fail('Proof hash does not equal proof id!', throws)
  }
  // Check if the signature is invalid.
  if (!ecc.verify(sig, id, pubkey)) {
    assert.fail('Proof signature is invalid!', throws)
  }
  // Check if the policy of the endorsement is valid.
  verify_policy(proof)
  return true
}

export function verify_policy (
  proof : Endorsement
) : void {
  void proof
}

export function compute_ref (
  content : string,
  params  : string[][] = []
) : string {
  let ref_hash  = Buff.str(content).digest.hex
  // If additional params are present:
  if (params.length > 0) {
    // Convert string arrays into a query string.
    const query_str = new URLSearchParams(params).toString()
    // Apply the query string to the reference hash.
    ref_hash = ref_hash + '?' + query_str
  }
  return ref_hash
}

export function get_param (
  label  : string,
  params : string[][]
) : string[] | undefined {
  const ret = params.find(e => e[0] === label)
  return (Array.isArray(ret) && ret.length > 1)
    ? ret.slice(1)
    : undefined
}

export function get_kind (
  params   : string[][],
  defaults : number
) : number {
  const param = get_param('kind', params)
  if (Array.isArray(param)) {
    return parse_kind(param[0])
  }
  return defaults
}

export function parse_ref (
  ref_link : string
) : [ link : string, params : string[][] ] {
  // Initialize our variables.
  let link = ref_link, params : string[][] = []
  // Check if query key is present:
  if (ref_link.includes('?')) {
    // Split link into hash and params.
    const link_data = ref_link.split('?')
    // Update link and params.
    link   = link_data[0]
    params = [ ...new URLSearchParams(link_data[1]) ]
  }
  return [ link, params ]
}

export function parse_kind (kind_str : string) : number {
  try {
    const kind = parseInt(kind_str)
    assert.max_num_value(kind, KIND_MAX)
    return kind
  } catch {
    throw new TypeError('Invalid kind value:' + kind_str)
  }
}

export function parse_proof (
  proof : Endorsement
) : ProofData {
  const [ ref, pubkey, id, sig, stamp ] = proof
  return { id, pubkey, ref, sig, stamp }
}

export function convert_to_event <T> (
  data  : T,
  proof : Endorsement
) : Event {
  // Stringify data.
  const content = util.stringify(data)
   // Unpack the proof.
  const { ref, pubkey, id, sig, stamp } = parse_proof(proof)
  // Parse the hash and params.
  const [ _, params ] = parse_ref(ref)
  // Get the kind value from params, if present.
  const kind = get_kind(params, KIND_DEFAULT)
  return { id, pubkey, sig, kind, content, created_at: stamp, tags: params }
}

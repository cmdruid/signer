import { Buff }       from '@cmdcode/buff'
import { get_pubkey } from '@cmdcode/crypto-tools/keys'

import {
  sign_msg,
  verify_sig
} from '@cmdcode/crypto-tools/signer'

import {
  Literal,
  Params,
  ProofData,
  ProofConfig,
  SignedEvent,
  ProofPolicy
} from '../types.js'

import * as assert from '../assert.js'

/**
 * Initial values for new proofs.
 */
const PROOF_DEFAULTS = {
  kind       : 20000,
  created_at : Math.floor(Date.now() / 1000),
  params     : []
}

/**
 * Create a new proof string using a provided
 * signing device and content string (plus params).
 */
export function create_proof (
  config : ProofConfig
) : ProofData {
  // Initialize config object.
  const conf = { ...PROOF_DEFAULTS, ...config }
  // Unpack config object.
  const { created_at : cat, kind : knd } = conf
  // Get pubkey of seckey.
  const pub = get_pubkey(conf.seckey, true).hex
  // Unpack parsed config object.
  const tag = parse_params(conf.params)
  // Build the pre-image that we will be hashing.
  const img = [ 0, pub, cat, knd, tag, conf.content ]
  // Compute the proof id from the image.
  const pid = Buff.json(img).digest.hex
  // Compute a signature for the given id.
  const sig = sign_msg(pid, conf.seckey, conf.options).hex
  // Normalize kind and stamp values.
  const cb  = Buff.num(cat, 4)
  const kb  = Buff.num(knd, 4)
  // Create the proof string.
  const hex = Buff.join([ kb, cb, pub, pid, sig ]).hex
  // Create the params string.
  const qry = encode_params(tag)
  // Return data object.
  return { cat, hex, knd, pid, pub, qry, sig, tag }
}

/**
 * Decode and parse a proof string
 * into a rich data object.
 */
export function parse_proof (
  hex  : string,
  qry ?: string
) : ProofData {
  // Convert the hex string into a data stream.
  const stream = Buff.hex(hex).stream
  // Assert the stream size is correct.
  assert.ok(stream.size === 136)
  // Parse the data stream.
  const knd = stream.read(4).num,
        cat = stream.read(4).num,
        pub = stream.read(32).hex,
        pid = stream.read(32).hex,
        sig = stream.read(64).hex,
        tag = decode_params(qry)
  // Return the proof object.
  return { cat, hex, knd, pid, pub, qry, sig, tag }
}

/**
 * Use regex to check if a proof string is valid.
 */
export function validate_proof (proof : string) {
  const regex = /^[0-9a-fA-F]{272}(?:\?[A-Za-z0-9_]+=[A-Za-z0-9_]+(?:&[A-Za-z0-9_]+=[A-Za-z0-9_]+)*)?$/
  if (!regex.test(proof)) {
    throw new Error('invalid proof format')
  }
}

/**
 * Verify a proof string along with
 * its matching content string.
 */
export function verify_proof (
  content : string,
  proof   : ProofData,
  policy ?: ProofPolicy
) : void {
  const { since, until } = policy ?? {}
  // Parse the proof data from the hex string.
  const { cat, knd, pub, pid, sig, tag } = proof
  // Parse the configuration from params.
  const tags = parse_params(tag)
  // Assemble the pre-image for the hashing function.
  const img = [ 0, pub, cat, knd, tags, content ]
  // Stringify and hash the preimage.
  const proof_hash = Buff.json(img).digest
  // Verify the proof:
  if (proof_hash.hex !== pid) {
    // Throw if the hash does not match our proof id.
    throw new Error('Proof hash does not equal proof id!')
  } else if (since !== undefined && cat < since) {
    // Throw if the timestamp is below the threshold.
    throw new Error(`Proof timestamp created below threshold: ${cat} < ${since}`)
  } else if (until !== undefined && cat > until) {
    // Throw if the timestamp is above the threshold.
    throw new Error(`Proof timestamp created above threshold: ${cat} > ${until}`)
  } else if (!verify_sig(sig, pid, pub)) {
    // Throw if the signature is invalid.
    throw new Error('Proof signature is invalid!')
  }
}

/**
 * Convert a proof string into a valid nostr note.
 */
export function proof_to_note (
  content : string,
  proof   : ProofData
) : SignedEvent {
  // Parse the proof data from the hex string.
  const { cat, knd, pub, pid, sig, tag } = proof
  // Return the proof formatted as a nostr event.
  return { kind : knd, content, tags : tag, pubkey: pub, id: pid, sig, created_at: cat }
}

/**
 * Parse params into an array of string arrays.
 */
export function parse_params (
  params : Params = []
) : string[][] {
  // Unpack the params array.
  if (!Array.isArray(params)) {
    params = Object.entries(params)
  }
  return params.map(([ k, ...v ]) => [ String(k), ...v.map(e => String(e)) ])
}

/**
 * Encode params into a url-safe query string.
 */
export function encode_params (
  params : Literal[][] | Record<string, Literal> = []
) : string {
  if (!Array.isArray(params)) {
    params = Object.entries(params)
  }
  // Convert all param data into strings.
  const strings = params.map(e => e.map(x => String(x)))
  // Return the params as a query string.
  return (params.length !== 0)
    ? '?' + new URLSearchParams(strings).toString()
    : ''
}

/**
 * Decode a query string into params.
 */
export function decode_params (str ?: string) : string[][] {
  // Return the query string as an array of params.
  return (typeof str === 'string')
    ? [ ...new URLSearchParams(str) ]
    : []
}

export function get_param (label : string, tags : string[][]) {
  const tag = tags.find(e => e[0] === label)
  return (tag !== undefined) ? tag[1] : undefined
}

export default {
  create   : create_proof,
  parse    : parse_proof,
  publish  : proof_to_note,
  validate : validate_proof,
  verify   : verify_proof
}

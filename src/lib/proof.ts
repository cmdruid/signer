import { Buff }       from '@cmdcode/buff'
import { verify_sig } from '@cmdcode/crypto-tools/signer'

import {
  Literal,
  Params,
  ProofData,
  ProofConfig,
  SignedEvent
} from '../types.js'

/**
 * Initial values for new proofs.
 */
const PROOF_DEFAULTS = {
  kind  : 0,
  stamp : 0,
  tags  : [] as Literal[][]
}

/**
 * Create a new proof string using a provided
 * signing device and content string (plus params).
 */
export async function create_proof (
  content : string,
  pubkey  : string,
  signer  : (msg : string) => Promise<string> | string,
  params ?: Params,
  defaults = PROOF_DEFAULTS
) : Promise<string> {
  const { kind, stamp, tags } = parse_config(params, defaults)
  // Build the pre-image that we will be hashing.
  const img = [ 0, pubkey, stamp, kind, tags, content ]
  // Compute the proof id from the image.
  const pid  = Buff.json(img).digest.hex
  // Compute a signature for the given id.
  return new Promise(async (res) => {
    const sig = await signer(pid)
    // Return proof as a hex string
    const proof = Buff.join([ pubkey, pid, sig ]).hex
    res(proof + encode_params(params))
  })
}

/**
 * Decode and parse a proof string
 * into a rich data object.
 */
export function parse_proof (proof : string) : ProofData {
  // Split the hex and query strings.
  const [ hexstr, query ] = proof.split('?')
  // Convert the hex string into a data stream.
  const stream = Buff.hex(hexstr).stream
  // Assert the stream size is correct.
  assert(stream.size === 128, `invalid proof size: ${stream.size} !== 128`)
  // Return a data object from the stream.
  return {
    pub    : stream.read(32).hex,
    pid    : stream.read(32).hex,
    sig    : stream.read(64).hex,
    params : decode_params(query)
  }
}

/**
 * Use regex to check if a proof string is valid.
 */
export function validate_proof (proof : string) : boolean {
  const regex = /^[0-9a-fA-F]{256}(?:\?[A-Za-z0-9_]+=[A-Za-z0-9_]+(?:&[A-Za-z0-9_]+=[A-Za-z0-9_]+)*)?$/
  return regex.test(proof)
}

/**
 * Verify a proof string along with
 * its matching content string.
 */
export function verify_proof (
  content  : string,
  proof    : string,
  options ?: ProofConfig
) : void {
  const { since, until } = options ?? {}
  // Parse the proof data from the hex string.
  const { pub, pid, sig, params } = parse_proof(proof)
  // Parse the configuration from params.
  const { kind, stamp, tags } = parse_config(params)
  // Assemble the pre-image for the hashing function.
  const img = [ 0, pub, stamp, kind, tags, content ]
  // Stringify and hash the preimage.
  const proof_hash = Buff.json(img).digest
  // Verify the proof:
  if (proof_hash.hex !== pid) {
    // Throw if the hash does not match our proof id.
    throw new Error('Proof hash does not equal proof id!')
  } else if (since !== undefined && stamp < since) {
    // Throw if the timestamp is below the threshold.
    throw new Error(`Proof timestamp below threshold: ${stamp} < ${since}`)
  } else if (until !== undefined && stamp > until) {
    // Throw if the timestamp is above the threshold.
    throw new Error(`Proof timestamp above threshold: ${stamp} > ${until}`)
  } else if (!verify_sig(sig, pid, pub)) {
    // Throw if the signature is invalid.
    throw new Error('Proof signature is invalid!')
  }
}

/**
 * Convert a proof string into a valid nostr note.
 */
export function create_event (
  content : string,
  proof   : string
) : SignedEvent {
  // Parse the proof data from the hex string.
  const { pub, pid, sig, params } = parse_proof(proof)
  // Parse the proof config from the params.
  const { kind, stamp, tags } = parse_config(params)
  // Return the proof formatted as a nostr event.
  return { kind, content, tags, pubkey: pub, id: pid, sig, created_at: stamp }
}

/**
 * Parse a proof's configuration
 * from the provided parameters.
 */
export function parse_config (
  params   : Params = [],
  defaults = PROOF_DEFAULTS
) : typeof PROOF_DEFAULTS {
  // Unpack the params array.
  if (!Array.isArray(params)) {
    params = Object.entries(params)
  }
  const { kind, stamp, ...rest } = Object.fromEntries(params)
  // Return the config data.
  return {
    tags  : Object.entries(rest).map(([ k, v ]) => [ k, String(v) ]),
    kind  : (kind  !== undefined) ? Number(kind)  : defaults.kind,
    stamp : (stamp !== undefined) ? Number(stamp) : defaults.stamp
  }
}

/**
 * Format and encode the paramaters
 * that are provided with new a proof.
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
 * Decode the parameters from a proof string.
 */
export function decode_params (str ?: string) : string[][] {
  // Return the query string as an array of params.
  return (typeof str === 'string')
    ? [ ...new URLSearchParams(str) ]
    : []
}

/**
 * Assertion utility method.
 */
function assert (
  value    : unknown,
  message ?: string
) : asserts value {
  if (value === false) {
    throw new Error(message ?? 'Assertion failed!')
  }
}

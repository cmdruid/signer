import { Buff, Bytes } from '@cmdcode/buff'
import { get_pubkey }  from '@cmdcode/crypto-tools/keys'

import {
  sign_msg,
  verify_sig
} from '@cmdcode/crypto-tools/signer'

import {
  Literal,
  Params,
  TokenData,
  TokenOptions,
  SignedEvent,
  TokenPolicy
} from '../types.js'

import * as assert from '../assert.js'

/**
 * Initial values for new tokens.
 */
const TOKEN_DEFAULTS = {
  kind       : 20000,
  created_at : Math.floor(Date.now() / 1000),
  params     : []
}

export function get_token_id (
  content  : string,
  pubkey   : string,
  options ?: TokenOptions
) {
  // Initialize config object.
  const opt = { ...TOKEN_DEFAULTS, ...options }
  // Unpack config object.
  const { created_at : cat, kind : knd } = opt
  // Unpack parsed config object.
  const tag = parse_params(opt.params)
  // Build the pre-image that we will be hashing.
  const img = [ 0, pubkey, cat, knd, tag, content ]
  // Compute the token id from the image.
  return Buff.json(img).digest.hex
}

/**
 * Create a new token token using a provided
 * signing device and content string (plus params).
 */
export function create_token (
  content  : string,
  seckey   : Bytes,
  options ?: TokenOptions
) : TokenData {
  // Initialize config object.
  const opt = { ...TOKEN_DEFAULTS, ...options }
  // Unpack config object.
  const { created_at : cat, kind : knd } = opt
  // Get pubkey of seckey.
  const pub = get_pubkey(seckey, true).hex
  // Unpack parsed config object.
  const tag = parse_params(opt.params)
  // Compute the token id from the image.
  const pid = get_token_id(content, pub, opt)
  // Compute a signature for the given id.
  const sig = sign_msg(pid, seckey).hex
  // Normalize kind and stamp values.
  const cb  = Buff.num(cat, 4)
  const kb  = Buff.num(knd, 4)
  // Create the token string.
  const hex = Buff.join([ kb, cb, pub, pid, sig ]).hex
  // Create the params string.
  const qry = encode_params(tag)
  // Create the full token string.
  const str = hex + qry
  // Return data object.
  return { cat, hex, knd, pid, pub, qry, sig, str, tag }
}

/**
 * Decode and parse a token string
 * into a rich data object.
 */
export function parse_token (
  tokenstr : string,
) : TokenData {
  const [ hex, qry ] = tokenstr.split('?')
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
        str = tokenstr,
        tag = decode_params(qry)
  // Return the token object.
  return { cat, hex, knd, pid, pub, qry, sig, str, tag }
}

/**
 * Use regex to check if a token string is valid.
 */
export function validate_token (tokenstr : string) {
  const regex = /^[0-9a-fA-F]{272}(?:\?[A-Za-z0-9_]+=[A-Za-z0-9_]+(?:&[A-Za-z0-9_]+=[A-Za-z0-9_]+)*)?$/
  if (!regex.test(tokenstr)) {
    throw new Error('invalid token format')
  }
}

/**
 * Verify a token string along with
 * its matching content string.
 */
export function verify_token (
  content : string,
  token   : TokenData | string,
  policy ?: TokenPolicy
) : void {
  if (typeof token === 'string') {
    token = parse_token(token)
  }
  // Unpack policy object.
  const { since, until } = policy ?? {}
  // Parse the token data from the hex string.
  const { cat, knd, pub, pid, sig, tag } = token
  // Parse the configuration from params.
  const tags = parse_params(tag)
  // Assemble the pre-image for the hashing function.
  const img = [ 0, pub, cat, knd, tags, content ]
  // Stringify and hash the preimage.
  const hash = Buff.json(img).digest.hex
  // Verify the token:
  if (hash !== pid) {
    // Throw if the hash does not match our token id.
    throw new Error('token id does not equal hash :' + hash)
  } else if (since !== undefined && cat < since) {
    // Throw if the timestamp is below the threshold.
    throw new Error(`token created before date: ${cat} < ${since}`)
  } else if (until !== undefined && cat > until) {
    // Throw if the timestamp is above the threshold.
    throw new Error(`token created after date: ${cat} > ${until}`)
  } else if (!verify_sig(sig, pid, pub)) {
    // Throw if the signature is invalid.
    throw new Error('token signature is invalid')
  }
}

/**
 * Convert a token string into a valid nostr note.
 */
export function publish_token (
  content : string,
  token   : TokenData
) : SignedEvent {
  // Parse the token data from the hex string.
  const { cat, knd, pub, pid, sig, tag } = token
  // Return the token formatted as a nostr event.
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
  return (typeof str === 'string' && str.length > 0)
    ? [ ...new URLSearchParams(str) ]
    : []
}

export function get_param (label : string, tags : string[][]) {
  const tag = tags.find(e => e[0] === label)
  return (tag !== undefined) ? tag[1] : undefined
}

export default {
  create   : create_token,
  parse    : parse_token,
  publish  : publish_token,
  validate : validate_token,
  verify   : verify_token
}

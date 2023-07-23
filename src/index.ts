import { ecc } from '@cmdcode/crypto-utils'

import { verify as mv } from '@cmdcode/musig2'

import * as assert  from './assert.js'
import * as note    from './proof.js'
import * as util    from './utils.js'

export * from './config.js'
export * from './Signer.js'
export * from './types.js'

export const Parse = {
  kind  : note.parse_kind,
  proof : note.parse_proof,
  ref   : note.parse_ref
}

export const Verify = {
  proof     : note.verify_proof,
  signature : ecc.verify,
  p_sig     : mv.psig,
  musig     : mv.musig,
  cosig     : mv.sig
}

export const Util = {
  assert,
  note,
  ...util
}

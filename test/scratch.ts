// Test is_parent and is_child
// Check out keypass hex and parsed

import { MasterKey } from '@cmdcode/signer'
// import { create_cred, encode_cred, parse_cred } from '../src/lib/cred.js'

const mkey = MasterKey.generate()
const cred = mkey.new_cred()

console.log('cred:', cred.toJSON())

console.log('cred id:', cred.signer.kid)

console.log('share:', JSON.stringify(cred.share(mkey.pubkey), null, 2))

console.log('is ref:',   cred.is_issuer(mkey.pubkey))
console.log('has cred:', mkey.has_cred(cred.toString()))
console.log('cred is root:',  cred.is_issued)

const credstr = cred.toString()

console.log('credstr:', credstr)

console.log('has cred:', mkey.has_cred(credstr))

const cred2 = mkey.get_cred(credstr)

console.log('cred2 id:', cred2.signer.kid)

// Test is_parent and is_child
// Check out keypass hex and parsed

import { Signer } from '@cmdcode/signer'

const signer = Signer.generate()

console.log(signer)

const child = signer.derive()

console.log('is child:', signer.is_child(child.passkey))
console.log('is_parent:', child.is_parent(signer.pubkey))

const child2 = child.derive()

console.log('is child:', signer.is_child(child2.passkey))
console.log('is_parent:', child2.is_parent(signer.pubkey))
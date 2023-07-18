import { Buff, Bytes } from '@cmdcode/buff-utils'

export function size (input : Bytes, size : number) : void {
  const bytes = Buff.bytes(input)
  if (bytes.length !== size) {
    throw new Error(`Invalid input size: ${bytes.hex} !== ${size}`)
  }
}

export function exists <T> (
  input ?: T
  ) : asserts input is T {
  if (typeof input === 'undefined') {
    throw new Error('Input is undefined!')
  }
}

export function min_value (
  bytes : Bytes,
  min   : bigint
) : void {
  const val = Buff.bytes(bytes).big
  if (val < min) {
    throw new TypeError(`Bytes integer value is too low: ${val} < ${min}`)
  }
}

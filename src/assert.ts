import { Buff, Bytes } from '@cmdcode/buff-utils'

export function size (input : Bytes, size : number) : void {
  const bytes = Buff.bytes(input)
  if (bytes.length !== size) {
    throw new Error(`Invalid input size: ${bytes.hex} !== ${size}`)
  }
}

export function exists <T> (
  input ?: T | null
  ) : asserts input is NonNullable<T> {
  if (typeof input === 'undefined' || input === null) {
    throw new Error('Input is null or undefined!')
  }
}

export function min_byte_value (
  bytes : Bytes,
  min   : bigint
) : void {
  const val = Buff.bytes(bytes).big
  if (val < min) {
    throw new TypeError(`Bytes integer value is too low: ${val} < ${min}`)
  }
}

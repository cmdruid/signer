import { Buff, Bytes } from '@cmdcode/buff'

export function ok (
  value    : unknown,
  message ?: string
) : asserts value {
  if (value === false) throw new Error(message ?? 'Assertion failed!')
}

export function size (input : Bytes, size : number) : void {
  const bytes = Buff.bytes(input)
  if (bytes.length !== size) {
    throw new Error(`Invalid input size: ${bytes.length} !== ${size}`)
  }
}

export function exists <T> (
  input ?: T | null
  ) : asserts input is NonNullable<T> {
  if (typeof input === 'undefined' || input === null) {
    throw new Error('Input is null or undefined!')
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

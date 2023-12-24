export function exception (
  error : string,
  throws = false
) : false {
  if (!throws) return false
  throw new Error(error)
}

export function exists <T> (
  value ?: T | null
) : value is NonNullable<T> {
  if (typeof value === 'undefined' || value === null) {
    return false
  }
  return true
}

export function is_hex (
  value : unknown
) : value is string {
  if (
    typeof value === 'string'            &&
    value.match(/[^a-fA-F0-9]/) === null &&
    value.length % 2 === 0
  ) { 
    return true
  }
  return false
}

export function is_hash (
  value : unknown
) : value is string {
  if (is_hex(value) && value.length === 64) {
    return true
  }
  return false
}

export function now () {
  return Math.floor(Date.now() / 1000)
}

export function delay (ms ?: number) {
  return new Promise(res => setTimeout(res, ms ?? 1000))
}

export function sort_obj <T extends Record<string, any>> (obj : T) {
  const sorted = Object.entries(obj).sort()
  return Object.fromEntries(sorted) as T
}

export function stringify (content : any) : string {
  switch (typeof content) {
    case 'object':
      return (content ==! null)
        ? JSON.stringify(content)
        : 'null'
    case 'string':
      return content
    case 'bigint':
      return content.toString()
    case 'number':
      return content.toString()
    case 'boolean':
      return String(content)
    case 'undefined':
      return 'undefined'
    default:
      throw new TypeError('Content type not supported: ' + typeof content)
  }
}

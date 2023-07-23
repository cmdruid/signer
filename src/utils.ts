export const now = () : number => {
  return Math.floor(Date.now() / 1000)
}

export function stringify (content : any) : string {
  switch (typeof content) {
    case 'string':
      return content
    case 'bigint':
      return content.toString()
    case 'number':
      return content.toString()
    case 'boolean':
      return String(content)
    case 'object':
      return JSON.stringify(content)
    default:
      throw new TypeError('Content type not supported: ' + typeof content)
  }
}

import { HDKey }    from '@scure/bip32'
import { VERSIONS } from '../const.js'

export function parse_extkey (extkey : string) {
  if (extkey.startsWith('xpub')) {
    return HDKey.fromExtendedKey(extkey, VERSIONS['main'])
  } else if (extkey.startsWith('tpub')) {
    return HDKey.fromExtendedKey(extkey, VERSIONS['test'])
  } else {
    throw new Error('unrecognized prefix: ' + extkey.slice(0, 4))
  }
}

/** @fileOverview Bit array codec implementations.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */
import * as bitArray from './bitArray.js'

/** Convert from a bitArray to an array of bytes. */
export function fromBits(arr) {
  var out = [],
    bl = bitArray.bitLength(arr),
    i,
    tmp
  for (i = 0; i < bl / 8; i++) {
    if ((i & 3) === 0) {
      tmp = arr[i / 4]
    }
    out.push(tmp >>> 24)
    tmp <<= 8
  }
  return out
}
/** Convert from an array of bytes to a bitArray. */
export function toBits(bytes) {
  var out = [],
    i,
    tmp = 0
  for (i = 0; i < bytes.length; i++) {
    tmp = (tmp << 8) | bytes[i]
    if ((i & 3) === 3) {
      out.push(tmp)
      tmp = 0
    }
  }
  if (i & 3) {
    out.push(bitArray.partial(8 * (i & 3), tmp))
  }
  return out
}

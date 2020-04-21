/**
 * @fileOverview Bit array codec implementations.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */
import * as bitArray from './bitArray.js'

/** Convert from a bitArray to a hex string. */
export function fromBits(arr) {
  var out = '',
    i
  for (i = 0; i < arr.length; i++) {
    out += ((arr[i] | 0) + 0xf00000000000).toString(16).substr(4)
  }
  return out.substr(0, bitArray.bitLength(arr) / 4) //.replace(/(.{8})/g, "$1 ");
}

/** Convert from a hex string to a bitArray. */
export function toBits(str) {
  var i,
    out = [],
    len
  str = str.replace(/\s|0x/g, '')
  len = str.length
  str = str + '00000000'
  for (i = 0; i < str.length; i += 8) {
    out.push(parseInt(str.substr(i, 8), 16) ^ 0)
  }
  return bitArray.clamp(out, len * 4)
}

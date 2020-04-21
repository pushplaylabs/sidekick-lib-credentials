/**
 * @fileOverview Bit array codec implementations.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */
import * as bitArray from './bitArray.js'

/**
 * The base64 alphabet.
 * @private
 */
const CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

/** Convert from a bitArray to a base64 string. */
export function fromBits(arr, _noEquals, _url) {
  var out = '',
    i,
    bits = 0,
    c = CHARS,
    ta = 0,
    bl = bitArray.bitLength(arr)
  if (_url) {
    c = c.substr(0, 62) + '-_'
  }
  for (i = 0; out.length * 6 < bl; ) {
    out += c.charAt((ta ^ (arr[i] >>> bits)) >>> 26)
    if (bits < 6) {
      ta = arr[i] << (6 - bits)
      bits += 26
      i++
    } else {
      ta <<= 6
      bits -= 6
    }
  }
  while (out.length & 3 && !_noEquals) {
    out += '='
  }
  return out
}

/** Convert from a base64 string to a bitArray */
export function toBits(str, _url) {
  str = str.replace(/\s|=/g, '')
  var out = [],
    i,
    bits = 0,
    c = CHARS,
    ta = 0,
    x
  if (_url) {
    c = c.substr(0, 62) + '-_'
  }
  for (i = 0; i < str.length; i++) {
    x = c.indexOf(str.charAt(i))
    if (x < 0) {
      throw new TypeError("this isn't base64!")
    }
    if (bits > 26) {
      bits -= 26
      out.push(ta ^ (x >>> bits))
      ta = x << (32 - bits)
    } else {
      bits += 6
      ta ^= x << (32 - bits)
    }
  }
  if (bits & 56) {
    out.push(bitArray.partial(bits & 56, ta, 1))
  }
  return out
}

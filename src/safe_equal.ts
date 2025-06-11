/*
 * @boringnode/encryption
 *
 * @license MIT
 * @copyright Boring Node
 */

import { timingSafeEqual } from 'node:crypto'

export function safeEqual(
  a: string | ArrayBuffer | SharedArrayBuffer | Uint8Array | Buffer,
  b: string | ArrayBuffer | SharedArrayBuffer | Uint8Array | Buffer
) {
  const bufferA = typeof a === 'string' ? Buffer.from(a, 'utf8') : Buffer.from(a as ArrayBuffer)
  const bufferB = typeof b === 'string' ? Buffer.from(b, 'utf8') : Buffer.from(b as ArrayBuffer)

  if (bufferA.length !== bufferB.length) {
    return false
  }

  return timingSafeEqual(bufferA, bufferB)
}

/*
 * @boringnode/encryption
 *
 * @license MIT
 * @copyright Boring Node
 */

import { timingSafeEqual, createHmac, randomBytes } from 'node:crypto'

const hmacKey = randomBytes(32)

export function safeEqual(
  a: string | ArrayBuffer | SharedArrayBuffer | Uint8Array | Buffer,
  b: string | ArrayBuffer | SharedArrayBuffer | Uint8Array | Buffer
) {
  const bufferA = typeof a === 'string' ? Buffer.from(a, 'utf8') : Buffer.from(a as ArrayBuffer)
  const bufferB = typeof b === 'string' ? Buffer.from(b, 'utf8') : Buffer.from(b as ArrayBuffer)

  const hmacA = createHmac('sha256', hmacKey).update(bufferA).digest()
  const hmacB = createHmac('sha256', hmacKey).update(bufferB).digest()

  return timingSafeEqual(hmacA, hmacB)
}

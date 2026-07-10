/*
 * @boringnode/encryption
 *
 * @license MIT
 * @copyright Boring Node
 */

import { test } from '@japa/runner'
import { base64UrlDecode, base64UrlEncode } from '../src/base64.ts'

test.group('base64', () => {
  const dataset: Buffer[] = [
    Buffer.alloc(0),
    Buffer.from('hello world', 'utf8'),
    Buffer.from('✓ à la ligne\n👋🏼', 'utf8'),
    Buffer.from([0x00, 0x01, 0x02, 0xde, 0xad, 0xbe, 0xef]),
    Buffer.from(Array.from({ length: 256 }, (_, i) => i)),
  ]

  test('encode and decode base64')
    .with(dataset)
    .run(({ assert }, buffer) => {
      const token = base64UrlEncode(buffer)
      const decoded = base64UrlDecode(token)

      assert.isNotNull(decoded)
      assert.deepEqual(Buffer.from(decoded!), buffer)
    })

  test('generate without padding', ({ assert }) => {
    const token = base64UrlEncode(Buffer.from('f'))

    assert.isFalse(token.endsWith('='))
  })

  test('reject non-canonical base64url values', ({ assert }) => {
    assert.isNull(base64UrlDecode('aGVsbG8='))
    assert.isNull(base64UrlDecode('aGVsbG8!'))
  })
})

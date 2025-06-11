/*
 * @boringnode/encryption
 *
 * @license MIT
 * @copyright Boring Node
 */

import { test } from '@japa/runner'
import { safeEqual } from '../src/safe_equal.js'

test.group('safeEqual', () => {
  test('return true on identical string', ({ assert }) => {
    assert.isTrue(safeEqual('lanz', 'lanz'))
  })

  test('return false on different strings (same length)', ({ assert }) => {
    assert.isFalse(safeEqual('lanz', 'lany'))
  })

  test('return false on different strings (different length)', ({ assert }) => {
    assert.isFalse(safeEqual('lanz', 'lanzzz'))
  })

  test('works with buffers', ({ assert }) => {
    const buffer1 = Buffer.from('lanz')
    const buffer2 = Buffer.from('lanz')
    const buffer3 = Buffer.from('lany')

    assert.isTrue(safeEqual(buffer1, buffer2))
    assert.isFalse(safeEqual(buffer1, buffer3))
  })

  test('works with ArrayBuffer', ({ assert }) => {
    const arrayBuffer1 = new Uint8Array([1, 2, 3]).buffer
    const arrayBuffer2 = new Uint8Array([1, 2, 3]).buffer
    const arrayBuffer3 = new Uint8Array([1, 2, 4]).buffer

    assert.isTrue(safeEqual(arrayBuffer1, arrayBuffer2))
    assert.isFalse(safeEqual(arrayBuffer1, arrayBuffer3))
  })
})

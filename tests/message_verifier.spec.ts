/*
 * @boringnode/encryption
 *
 * @license MIT
 * @copyright Boring Node
 */

import { test } from '@japa/runner'
import { MessageVerifier } from '../src/message_verifier.js'
import { base64UrlDecode } from '../src/base64.ts'

const SECRET = 'averylongradom32charactersstring'

test.group('MessageVerifier', () => {
  test('disallow signing null and undefined values', ({ assert }) => {
    const messageVerifier = new MessageVerifier([SECRET])

    assert.throws(() => messageVerifier.sign(null), 'Cannot sign "null" value')
    assert.throws(() => messageVerifier.sign(undefined), 'Cannot sign "undefined" value')
  })

  test('sign an object using a secret', ({ assert }) => {
    const messageVerifier = new MessageVerifier([SECRET])
    const signed = messageVerifier.sign({ username: 'virk' })

    assert.equal(base64UrlDecode(signed.split('.')[0], 'utf8'), '{"message":{"username":"virk"}}')
  })

  test('sign an object with purpose', ({ assert }) => {
    const messageVerifier = new MessageVerifier([SECRET])
    const signed = messageVerifier.sign({ username: 'virk' }, undefined, 'login')

    assert.equal(
      base64UrlDecode(signed.split('.')[0], 'utf8'),
      '{"message":{"username":"virk"},"purpose":"login"}'
    )
  })

  test('return null when unsigning non-string values', ({ assert }) => {
    const messageVerifier = new MessageVerifier([SECRET])

    // @ts-expect-error
    assert.isNull(messageVerifier.unsign({}))
    // @ts-expect-error
    assert.isNull(messageVerifier.unsign(null))
    // @ts-expect-error
    assert.isNull(messageVerifier.unsign(22))
  })

  test('unsign value', ({ assert }) => {
    const messageVerifier = new MessageVerifier([SECRET])
    const signed = messageVerifier.sign({ username: 'virk' })
    const unsigned = messageVerifier.unsign(signed)

    assert.deepEqual(unsigned, { username: 'virk' })
  })

  test('return null when unable to decode it', ({ assert }) => {
    const messageVerifier = new MessageVerifier([SECRET])

    assert.isNull(messageVerifier.unsign('hello.world'))
  })

  test('return null when hash separator is missing', ({ assert }) => {
    const messageVerifier = new MessageVerifier([SECRET])

    assert.isNull(messageVerifier.unsign('helloworld'))
  })

  test('return null when hash was touched', ({ assert }) => {
    const messageVerifier = new MessageVerifier([SECRET])
    const signed = messageVerifier.sign({ username: 'virk' })

    assert.isNull(messageVerifier.unsign(signed.slice(0, -2)))
  })
})

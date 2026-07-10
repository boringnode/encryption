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
  test('fail when secrets array is empty', ({ assert }) => {
    assert.throws(
      () => new MessageVerifier([]),
      'Missing keys. At least one key is required to encrypt values'
    )
  })

  test('fail when a signing secret is insecure', ({ assert }) => {
    assert.throws(
      () => new MessageVerifier(['']),
      'Missing key. The key is required to encrypt values'
    )
    assert.throws(
      () => new MessageVerifier(['hello-world']),
      'The value of your key should be at least 16 characters long'
    )
  })

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

  test('unsign legacy value with purpose', ({ assert }) => {
    const messageVerifier = new MessageVerifier([SECRET])
    const signed =
      'eyJtZXNzYWdlIjp7InVzZXJuYW1lIjoibGFueiJ9LCJwdXJwb3NlIjoibG9naW4ifQ.cCVoXFC8F2J3vnU6Gkrjl6N2_KtqdF6XH8k2Uf5I0vg'

    assert.deepEqual(messageVerifier.unsign(signed, 'login'), { username: 'lanz' })
    assert.isNull(messageVerifier.unsign(signed))
    assert.isNull(messageVerifier.unsign(signed, 'register'))
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

  test('return null when an unsigned segment is appended', ({ assert }) => {
    const messageVerifier = new MessageVerifier([SECRET])
    const signed = messageVerifier.sign({ username: 'virk' })

    assert.isNull(messageVerifier.unsign(`${signed}.unsigned`))
  })
})

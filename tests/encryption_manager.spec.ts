/*
 * @boringnode/encryption
 *
 * @license MIT
 * @copyright Boring Node
 */

import { test } from '@japa/runner'
import { EncryptionManager } from '../src/encryption_manager.js'
import { ChaCha20Poly1305 } from '../src/drivers/chacha20_poly1305.ts'
import { MessageVerifier } from '../src/message_verifier.js'
import type { EncryptionDriverContract } from '../src/types/main.js'

const SECRET = 'averylongradom32charactersstring'
const driverConfig = {
  id: 'nova',
  keys: [SECRET],
}

test.group('Encryption manager', () => {
  test('create encryption instance from the manager', ({ assert, expectTypeOf }) => {
    const manager = new EncryptionManager({
      default: 'legacy',
      list: {
        legacy: () => new ChaCha20Poly1305(driverConfig),
      },
    })

    expectTypeOf(manager.use).parameter(0).toEqualTypeOf<'legacy' | undefined>()

    expectTypeOf(manager.use('legacy')).toEqualTypeOf<EncryptionDriverContract>()

    assert.instanceOf(manager.use('legacy'), ChaCha20Poly1305)
  })

  test('cache encryption instance', ({ assert, expectTypeOf }) => {
    const manager = new EncryptionManager({
      default: 'legacy',
      list: {
        legacy: () => new ChaCha20Poly1305(driverConfig),
        legacy1: () => new ChaCha20Poly1305(driverConfig),
      },
    })

    expectTypeOf(manager.use).parameter(0).toEqualTypeOf<'legacy' | 'legacy1' | undefined>()

    expectTypeOf(manager.use('legacy')).toEqualTypeOf<EncryptionDriverContract>()
    expectTypeOf(manager.use('legacy1')).toEqualTypeOf<EncryptionDriverContract>()

    assert.strictEqual(manager.use('legacy'), manager.use('legacy'))
    assert.notStrictEqual(manager.use('legacy'), manager.use('legacy1'))
  })

  test('use default encryption driver', ({ assert }) => {
    const manager = new EncryptionManager({
      default: 'legacy',
      list: {
        legacy: () => new ChaCha20Poly1305(driverConfig),
      },
    })

    assert.strictEqual(manager.use(), manager.use('legacy'))
  })

  test('fail when default encrypter is not configured', ({ assert }) => {
    const manager = new EncryptionManager({
      list: {
        legacy: () => new ChaCha20Poly1305(driverConfig),
      },
    })

    assert.throws(
      () => manager.use(),
      'Cannot create encryption instance. No default encryption is defined in the config'
    )
  })

  test('use message verifier', ({ assert }) => {
    const manager = new EncryptionManager({
      default: 'legacy',
      list: {
        legacy: () => new ChaCha20Poly1305(driverConfig),
      },
    })

    assert.instanceOf(manager.getMessageVerifier(), MessageVerifier)
  })

  test('fail when getting message verifier without default encrypter configured', ({ assert }) => {
    const manager = new EncryptionManager({
      list: {
        legacy: () => new ChaCha20Poly1305(driverConfig),
      },
    })

    assert.throws(
      () => manager.getMessageVerifier(),
      'Cannot create encryption instance. No default encryption is defined in the config'
    )
  })

  test('encrypt text using the default driver', ({ assert }) => {
    const manager = new EncryptionManager({
      default: 'legacy',
      list: {
        legacy: () => new ChaCha20Poly1305(driverConfig),
      },
    })

    const encrypted = manager.encrypt('hello world')
    assert.notEqual(encrypted, 'hello world')
  })

  test('decrypt text using the default driver', ({ assert }) => {
    const manager = new EncryptionManager({
      default: 'legacy',
      list: {
        legacy: () => new ChaCha20Poly1305(driverConfig),
      },
    })

    const encrypted = manager.encrypt('hello world')
    assert.deepEqual(manager.decrypt(encrypted), 'hello world')
  })
})

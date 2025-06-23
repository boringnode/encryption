/*
 * @boringnode/encryption
 *
 * @license MIT
 * @copyright Boring Node
 */

import { test } from '@japa/runner'
import { EncryptionManager } from '../src/encryption_manager.js'
import { Legacy } from '../src/drivers/legacy.js'
import { MessageVerifier } from '../src/message_verifier.js'
import { EncryptionDriverContract } from '../src/types/main.js'

const SECRET = 'averylongradom32charactersstring'

test.group('Encryption manager', () => {
  test('create encryption instance from the manager', ({ assert, expectTypeOf }) => {
    const manager = new EncryptionManager({
      default: 'legacy',
      list: {
        legacy: () => new Legacy({ keys: [SECRET] }),
      },
    })

    expectTypeOf(manager.use).parameter(0).toEqualTypeOf<'legacy' | undefined>()

    expectTypeOf(manager.use('legacy')).toEqualTypeOf<EncryptionDriverContract>()

    assert.instanceOf(manager.use('legacy'), Legacy)
  })

  test('cache encryption instance', ({ assert, expectTypeOf }) => {
    const manager = new EncryptionManager({
      default: 'legacy',
      list: {
        legacy: () => new Legacy({ keys: [SECRET] }),
        legacy1: () => new Legacy({ keys: [SECRET] }),
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
        legacy: () => new Legacy({ keys: [SECRET] }),
      },
    })

    assert.strictEqual(manager.use(), manager.use('legacy'))
  })

  test('fail when default encrypter is not configured', ({ assert }) => {
    const manager = new EncryptionManager({
      list: {
        legacy: () => new Legacy({ keys: [SECRET] }),
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
        legacy: () => new Legacy({ keys: [SECRET] }),
      },
    })

    assert.instanceOf(manager.getMessageVerifier(), MessageVerifier)
  })

  test('fail when getting message verifier without default encrypter configured', ({ assert }) => {
    const manager = new EncryptionManager({
      list: {
        legacy: () => new Legacy({ keys: [SECRET] }),
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
        legacy: () => new Legacy({ keys: [SECRET] }),
      },
    })

    const encrypted = manager.encrypt('hello world')
    assert.notEqual(encrypted, 'hello world')
  })

  test('decrypt text using the default driver', ({ assert }) => {
    const manager = new EncryptionManager({
      default: 'legacy',
      list: {
        legacy: () => new Legacy({ keys: [SECRET] }),
      },
    })

    const encrypted = manager.encrypt('hello world')
    assert.deepEqual(manager.decrypt(encrypted), 'hello world')
  })
})

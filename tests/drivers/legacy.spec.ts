/*
 * @boringnode/encryption
 *
 * @license MIT
 * @copyright Boring Node
 */

import { test } from '@japa/runner'
import { Legacy } from '../../src/drivers/legacy.js'

const SECRET = 'averylongradom32charactersstring'

test.group('Legacy', () => {
  test('fail when secret is missing', ({ assert }) => {
    assert.throws(
      // @ts-expect-error
      () => new Legacy({ key: null }),
      'Missing key. The key is required to encrypt values'
    )
  })

  test('fail when secret is not bigger than 16 chars', ({ assert }) => {
    assert.throws(
      () => new Legacy({ key: 'helloworld' }),
      'The value of your key should be at least 16 characters long'
    )
  })

  test('encrypt value', ({ assert }) => {
    const driver = new Legacy({ key: SECRET })

    assert.notEqual(driver.encrypt('hello-world'), 'hello-world')
    assert.equal(driver.decrypt(driver.encrypt('hello-world')), 'hello-world')
  })

  test('encrypt an object with a secret', ({ assert }) => {
    const driver = new Legacy({ key: SECRET })
    const encrypted = driver.encrypt({ username: 'virk' })

    assert.exists(encrypted)
  })

  test('ensure iv is random for each encryption call', ({ assert }) => {
    const driver = new Legacy({ key: SECRET })

    assert.notEqual(driver.encrypt({ username: 'virk' }), driver.encrypt({ username: 'virk' }))
  })

  test('return null when decrypting non-string values', ({ assert }) => {
    const driver = new Legacy({ key: SECRET })

    // @ts-expect-error
    assert.isNull(driver.decrypt(null))
  })

  test('decrypt encrypted value', ({ assert }) => {
    const driver = new Legacy({ key: SECRET })
    const encrypted = driver.encrypt({ username: 'virk' })

    assert.deepEqual(driver.decrypt(encrypted), { username: 'virk' })
  })

  test('return null when value is in invalid format', ({ assert }) => {
    const driver = new Legacy({ key: SECRET })

    assert.isNull(driver.decrypt('foo'))
  })

  test('return null when unable to decode encrypted value', ({ assert }) => {
    const driver = new Legacy({ key: SECRET })

    assert.isNull(driver.decrypt('foo.bar.baz'))
  })

  test('return null when hash is tampered', ({ assert }) => {
    const driver = new Legacy({ key: SECRET })
    const encrypted = driver.encrypt({ username: 'virk' })

    assert.isNull(driver.decrypt(encrypted.slice(0, -2)))
  })

  test('return null when encrypted value is tampered', ({ assert }) => {
    const driver = new Legacy({ key: SECRET })
    const encrypted = driver.encrypt({ username: 'virk' })

    assert.isNull(driver.decrypt(encrypted.slice(2)))
  })

  test('return null when iv value is tampered', ({ assert }) => {
    const driver = new Legacy({ key: SECRET })
    const encrypted = driver.encrypt({ username: 'virk' })

    const ivIndex = encrypted.indexOf('--') + 2
    const part1 = encrypted.slice(0, ivIndex)
    const part2 = encrypted.slice(ivIndex).slice(2)

    assert.isNull(driver.decrypt(`${part1}${part2}`))
  })

  test('return null when purpose is missing during decrypt', ({ assert }) => {
    const driver = new Legacy({ key: SECRET })
    const encrypted = driver.encrypt({ username: 'virk' }, undefined, 'login')

    assert.isNull(driver.decrypt(encrypted))
  })

  test('return null when purpose is defined only during decrypt', ({ assert }) => {
    const driver = new Legacy({ key: SECRET })
    const encrypted = driver.encrypt({ username: 'virk' })

    assert.isNull(driver.decrypt(encrypted, 'login'))
  })

  test('return null when purpose are not same', ({ assert }) => {
    const driver = new Legacy({ key: SECRET })
    const encrypted = driver.encrypt({ username: 'virk' }, undefined, 'register')

    assert.isNull(driver.decrypt(encrypted, 'login'))
  })

  test('decrypt when purpose are same', ({ assert }) => {
    const driver = new Legacy({ key: SECRET })
    const encrypted = driver.encrypt({ username: 'virk' }, undefined, 'register')

    assert.deepEqual(driver.decrypt(encrypted, 'register'), { username: 'virk' })
  })
})

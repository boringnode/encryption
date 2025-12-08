/*
 * @boringnode/encryption
 *
 * @license MIT
 * @copyright Boring Node
 */

import { test } from '@japa/runner'
import { AES256CBC } from '../../src/drivers/aes_256_cbc.js'

const SECRET = 'averylongradom32charactersstring'

test.group('AES-256-CBC', () => {
  test('fail when secret is missing', ({ assert }) => {
    assert.throws(
      // @ts-expect-error
      () => new AES256CBC({ key: null }),
      'Missing key. The key is required to encrypt values'
    )
  })

  test('fail when secret is not bigger than 16 chars', ({ assert }) => {
    assert.throws(
      () => new AES256CBC({ id: 'lanz', key: 'hello-world' }),
      'The value of your key should be at least 16 characters long'
    )
  })

  test('fail when id is missing', ({ assert }) => {
    assert.throws(
      // @ts-expect-error
      () => new AES256CBC({ key: SECRET }),
      'Missing id. The id is required to encrypt values'
    )
  })

  test('encrypt value', ({ assert }) => {
    const encryption = new AES256CBC({ id: 'lanz', key: SECRET })
    assert.notEqual(encryption.encrypt('hello-world'), 'hello-world')
  })

  test('encrypt an object with a secret', ({ assert }) => {
    const driver = new AES256CBC({ id: 'lanz', key: SECRET })
    const encrypted = driver.encrypt({ username: 'lanz' })

    assert.exists(encrypted)
  })

  test('ensure iv is random for each encryption call', ({ assert }) => {
    const driver = new AES256CBC({ id: 'lanz', key: SECRET })

    assert.notEqual(driver.encrypt({ username: 'lanz' }), driver.encrypt({ username: 'lanz' }))
  })

  test('return null when decrypting not the same id', ({ assert }) => {
    const driver = new AES256CBC({ id: 'lanz', key: SECRET })

    assert.isNull(
      driver.decrypt(
        'virk.3e4b75c4c54a3ccac85e7ce445dacd6a87d73512cd670079bce8797cf4e80f46.416c05b78dfd6755716b52323a46c93a.uk_njXJ4OzWHMKchYTpAZkQBl7IXVnbmOU4n7Nw525A'
      )
    )
  })

  test('return null when decrypting not the same format', ({ assert }) => {
    const driver = new AES256CBC({ id: 'lanz', key: SECRET })

    assert.isNull(
      driver.decrypt(
        'lanz.416c05b78dfd6755716b52323a46c93a.uk_njXJ4OzWHMKchYTpAZkQBl7IXVnbmOU4n7Nw525A'
      )
    )
  })

  test('return null when decrypting non-string values', ({ assert }) => {
    const driver = new AES256CBC({ id: 'lanz', key: SECRET })

    // @ts-expect-error
    assert.isNull(driver.decrypt(null))
  })

  test('decrypt encrypted value', ({ assert }) => {
    const driver = new AES256CBC({ id: 'lanz', key: SECRET })

    assert.deepEqual(
      driver.decrypt(
        'lanz.gA6W70l7mCUpGW7BJPUhgAhpLRSmbh8qV8oRM62d7Jg.jQmpmEF3_z4a7N6KZ0HdxQ.WIIOA2Rm1wejdioEecWJAUvXC_3gqqYrsLvAvj5eaQc.4oTirrLj_Q9ituhhcDcx6LOTGYTWKFviDvc8zcbDtlU'
      ),
      { username: 'lanz' }
    )
  })

  test('return null when value is in invalid format', ({ assert }) => {
    const driver = new AES256CBC({ id: 'lanz', key: SECRET })

    assert.isNull(driver.decrypt('lanz.aes256cbc.foo'))
  })

  test('return null when unable to decode encrypted value', ({ assert }) => {
    const driver = new AES256CBC({ id: 'lanz', key: SECRET })

    assert.isNull(driver.decrypt('lanz.aes256cbc.foo.bar.baz'))
  })

  test('return null when hash is tampered', ({ assert }) => {
    const driver = new AES256CBC({ id: 'lanz', key: SECRET })
    const encrypted = driver.encrypt({ username: 'lanz' })

    assert.isNull(driver.decrypt(encrypted.slice(0, -2)))
  })

  test('return null when encrypted value is tampered', ({ assert }) => {
    const driver = new AES256CBC({ id: 'lanz', key: SECRET })
    const encrypted = driver.encrypt({ username: 'lanz' })

    assert.isNull(driver.decrypt(encrypted.slice(2)))
  })

  test('return null when iv value is tampered', ({ assert }) => {
    const driver = new AES256CBC({ id: 'lanz', key: SECRET })

    const encrypted = driver.encrypt({ username: 'lanz' })

    const ivIndex = encrypted.indexOf('--') + 2
    const part1 = encrypted.slice(0, ivIndex)
    const part2 = encrypted.slice(ivIndex).slice(2)

    assert.isNull(driver.decrypt(`${part1}${part2}`))
  })

  test('return null when purpose is missing during decrypt', ({ assert }) => {
    const driver = new AES256CBC({ id: 'lanz', key: SECRET })
    const encrypted = driver.encrypt({ username: 'lanz' }, undefined, 'login')

    assert.isNull(driver.decrypt(encrypted))
  })

  test('return null when purpose is defined only during decrypt', ({ assert }) => {
    const driver = new AES256CBC({ id: 'lanz', key: SECRET })
    const encrypted = driver.encrypt({ username: 'lanz' })

    assert.isNull(driver.decrypt(encrypted, 'login'))
  })

  test('return null when purpose are not same', ({ assert }) => {
    const driver = new AES256CBC({ id: 'lanz', key: SECRET })
    const encrypted = driver.encrypt({ username: 'lanz' }, undefined, 'register')

    assert.isNull(driver.decrypt(encrypted, 'login'))
  })

  test('decrypt when purpose are same', ({ assert }) => {
    const driver = new AES256CBC({ id: 'lanz', key: SECRET })
    const encrypted = driver.encrypt({ username: 'lanz' }, undefined, 'register')

    assert.deepEqual(driver.decrypt(encrypted, 'register'), { username: 'lanz' })
  })
})

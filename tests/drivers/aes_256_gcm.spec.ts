/*
 * @boringnode/encryption
 *
 * @license MIT
 * @copyright Boring Node
 */

import { test } from '@japa/runner'
import { AES256GCM } from '../../src/drivers/aes_256_gcm.js'

const SECRET = 'averylongradom32charactersstring'

test.group('AES-256-GCM', () => {
  test('fail when secret is missing', ({ assert }) => {
    assert.throws(
      // @ts-expect-error
      () => new AES256GCM({ keys: [null] }),
      'Missing key. The key is required to encrypt values'
    )
  })

  test('fail when secret is not bigger than 16 chars', ({ assert }) => {
    assert.throws(
      () => new AES256GCM({ id: 'lanz', keys: ['hello-world'] }),
      'The value of your key should be at least 16 characters long'
    )
  })

  test('fail when id is missing', ({ assert }) => {
    assert.throws(
      // @ts-expect-error
      () => new AES256GCM({ keys: [SECRET] }),
      'Missing id. The id is required to encrypt values'
    )
  })

  test('encrypt value', ({ assert }) => {
    const driver = new AES256GCM({ id: 'lanz', keys: [SECRET] })

    assert.notEqual(driver.encrypt('hello-world'), 'hello-world')
  })

  test('encrypt an object with a secret', ({ assert }) => {
    const driver = new AES256GCM({ id: 'lanz', keys: [SECRET] })
    const encrypted = driver.encrypt({ username: 'lanz' })

    assert.exists(encrypted)
  })

  test('ensure iv is random for each encryption call', ({ assert }) => {
    const driver = new AES256GCM({ id: 'lanz', keys: [SECRET] })

    assert.notEqual(driver.encrypt({ username: 'lanz' }), driver.encrypt({ username: 'lanz' }))
  })

  test('return null when decrypting not the same id', ({ assert }) => {
    const driver = new AES256GCM({ id: 'lanz', keys: [SECRET] })

    assert.isNull(
      driver.decrypt(
        'virk.dc0557176747dd4dba5445d27e20d865511aee3a3350c76caf27e9a3a524d3.8f7b458370aa80c7680157f81486afde.fb872925a922f735e9d9985ddfb3cae2.urTvWb1cis36VstavYyDDBWFyfL-k19EdAOs6VW8PpE'
      )
    )
  })

  test('return null when decrypting not the same format', ({ assert }) => {
    const driver = new AES256GCM({ id: 'lanz', keys: [SECRET] })

    assert.isNull(
      driver.decrypt(
        'lanz.8f7b458370aa80c7680157f81486afde.fb872925a922f735e9d9985ddfb3cae2.urTvWb1cis36VstavYyDDBWFyfL-k19EdAOs6VW8PpE'
      )
    )
  })

  test('return null when decrypting non-string values', ({ assert }) => {
    const driver = new AES256GCM({ id: 'lanz', keys: [SECRET] })

    // @ts-expect-error
    assert.isNull(driver.decrypt(null))
  })

  test('decrypt encrypted value', ({ assert }) => {
    const driver = new AES256GCM({ id: 'lanz', keys: [SECRET] })

    assert.deepEqual(
      driver.decrypt(
        'lanz.JFPf0dF5fxMF_l8XzGkxKyXuiwwfGbW8HQhmZ0TEMA.bHgH2t61PsbFIdq4.GtWD6AzejaHpFLBk05PReA'
      ),
      { username: 'lanz' }
    )
  })

  test('return null when value is in invalid format', ({ assert }) => {
    const driver = new AES256GCM({ id: 'lanz', keys: [SECRET] })

    assert.isNull(driver.decrypt('lanz.aes256gcm.foo'))
  })

  test('return null when unable to decode encrypted value', ({ assert }) => {
    const driver = new AES256GCM({ id: 'lanz', keys: [SECRET] })

    assert.isNull(driver.decrypt('lanz.xx.bHgH2t61PsbFIdq4.GtWD6AzejaHpFLBk05PReA'))
  })

  test('return null when unable to decode iv', ({ assert }) => {
    const token = 'lanz.JFPf0dF5fxMF_l8XzGkxKyXuiwwfGbW8HQhmZ0TEMA.xx.GtWD6AzejaHpFLBk05PReA'
    const driver = new AES256GCM({ id: 'lanz', keys: [SECRET] })

    assert.isNull(driver.decrypt(token))
  })

  test('return null when unable to decode tag', ({ assert }) => {
    const token = 'lanz.JFPf0dF5fxMF_l8XzGkxKyXuiwwfGbW8HQhmZ0TEMA.bHgH2t61PsbFIdq4.xx'
    const driver = new AES256GCM({ id: 'lanz', keys: [SECRET] })

    assert.isNull(driver.decrypt(token))
  })

  test('return null when encrypted value is tampered', ({ assert }) => {
    const driver = new AES256GCM({ id: 'lanz', keys: [SECRET] })
    const encrypted = driver.encrypt({ username: 'lanz' })

    assert.isNull(driver.decrypt(encrypted.slice(2)))
  })

  test('return null when iv value is tampered', ({ assert }) => {
    const driver = new AES256GCM({ id: 'lanz', keys: [SECRET] })
    const encrypted = driver.encrypt({ username: 'lanz' })

    const ivIndex = encrypted.indexOf('--') + 2
    const part1 = encrypted.slice(0, ivIndex)
    const part2 = encrypted.slice(ivIndex).slice(2)

    assert.isNull(driver.decrypt(`${part1}${part2}`))
  })

  test('return null when purpose is missing during decrypt', ({ assert }) => {
    const driver = new AES256GCM({ id: 'lanz', keys: [SECRET] })
    const encrypted = driver.encrypt({ username: 'lanz' }, undefined, 'login')

    assert.isNull(driver.decrypt(encrypted))
  })

  test('return null when purpose is defined only during decrypt', ({ assert }) => {
    const driver = new AES256GCM({ id: 'lanz', keys: [SECRET] })
    const encrypted = driver.encrypt({ username: 'lanz' })

    assert.isNull(driver.decrypt(encrypted, 'login'))
  })

  test('return null when purpose are not same', ({ assert }) => {
    const driver = new AES256GCM({ id: 'lanz', keys: [SECRET] })
    const encrypted = driver.encrypt({ username: 'lanz' }, undefined, 'register')

    assert.isNull(driver.decrypt(encrypted, 'login'))
  })

  test('decrypt when purpose are same', ({ assert }) => {
    const driver = new AES256GCM({ id: 'lanz', keys: [SECRET] })
    const encrypted = driver.encrypt({ username: 'lanz' }, undefined, 'register')

    assert.deepEqual(driver.decrypt(encrypted, 'register'), { username: 'lanz' })
  })
})

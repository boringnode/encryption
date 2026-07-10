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
      () => new AES256GCM({ key: null }),
      'Missing key. The key is required to encrypt values'
    )
  })

  test('fail when secret is not bigger than 16 chars', ({ assert }) => {
    assert.throws(
      () => new AES256GCM({ id: 'lanz', key: 'hello-world' }),
      'The value of your key should be at least 16 characters long'
    )
  })

  test('fail when id is missing', ({ assert }) => {
    assert.throws(
      // @ts-expect-error
      () => new AES256GCM({ key: SECRET }),
      'Missing id. The id is required to encrypt values'
    )
  })

  test('fail when id contains separator', ({ assert }) => {
    assert.throws(
      () => new AES256GCM({ id: 'lan.z', key: SECRET }),
      'Invalid id. The id must be a non-empty string and cannot contain "."'
    )
  })

  test('fail when id is empty', ({ assert }) => {
    assert.throws(
      () => new AES256GCM({ id: '', key: SECRET }),
      'Invalid id. The id must be a non-empty string and cannot contain "."'
    )
  })

  test('encrypt value', ({ assert }) => {
    const driver = new AES256GCM({ id: 'lanz', key: SECRET })

    assert.notEqual(driver.encrypt('hello-world'), 'hello-world')
  })

  test('encrypt an object with a secret', ({ assert }) => {
    const driver = new AES256GCM({ id: 'lanz', key: SECRET })
    const encrypted = driver.encrypt({ username: 'lanz' })

    assert.exists(encrypted)
  })

  test('ensure iv is random for each encryption call', ({ assert }) => {
    const driver = new AES256GCM({ id: 'lanz', key: SECRET })

    assert.notEqual(driver.encrypt({ username: 'lanz' }), driver.encrypt({ username: 'lanz' }))
  })

  test('return null when decrypting not the same id', ({ assert }) => {
    const driver = new AES256GCM({ id: 'lanz', key: SECRET })

    assert.isNull(
      driver.decrypt(
        'virk.dc0557176747dd4dba5445d27e20d865511aee3a3350c76caf27e9a3a524d3.8f7b458370aa80c7680157f81486afde.fb872925a922f735e9d9985ddfb3cae2.urTvWb1cis36VstavYyDDBWFyfL-k19EdAOs6VW8PpE'
      )
    )
  })

  test('return null when decrypting not the same format', ({ assert }) => {
    const driver = new AES256GCM({ id: 'lanz', key: SECRET })

    assert.isNull(
      driver.decrypt(
        'lanz.8f7b458370aa80c7680157f81486afde.fb872925a922f735e9d9985ddfb3cae2.urTvWb1cis36VstavYyDDBWFyfL-k19EdAOs6VW8PpE'
      )
    )
  })

  test('return null when decrypting non-string values', ({ assert }) => {
    const driver = new AES256GCM({ id: 'lanz', key: SECRET })

    // @ts-expect-error
    assert.isNull(driver.decrypt(null))
  })

  test('decrypt encrypted value', ({ assert }) => {
    const driver = new AES256GCM({ id: 'lanz', key: SECRET })

    assert.deepEqual(
      driver.decrypt(
        'lanz.JFPf0dF5fxMF_l8XzGkxKyXuiwwfGbW8HQhmZ0TEMA.bHgH2t61PsbFIdq4.GtWD6AzejaHpFLBk05PReA'
      ),
      { username: 'lanz' }
    )
  })

  test('decrypt legacy encrypted value with purpose', ({ assert }) => {
    const driver = new AES256GCM({ id: 'lanz', key: SECRET })
    const encrypted =
      'lanz.E6uh6HnxtJ18g_DRHXSp9-36KGqqlvYsnxqLslhw5w.AAECAwQFBgcICQoL.x0Cu8lvVZoTpnzXIYhUG5g'

    assert.deepEqual(driver.decrypt(encrypted, 'login'), { username: 'lanz' })
    assert.isNull(driver.decrypt(encrypted))
    assert.isNull(driver.decrypt(encrypted, 'register'))
  })

  test('return null when value is in invalid format', ({ assert }) => {
    const driver = new AES256GCM({ id: 'lanz', key: SECRET })

    assert.isNull(driver.decrypt('lanz.aes256gcm.foo'))
  })

  test('return null when unable to decode encrypted value', ({ assert }) => {
    const driver = new AES256GCM({ id: 'lanz', key: SECRET })

    assert.isNull(driver.decrypt('lanz.xx.bHgH2t61PsbFIdq4.GtWD6AzejaHpFLBk05PReA'))
  })

  test('return null when unable to decode iv', ({ assert }) => {
    const token = 'lanz.JFPf0dF5fxMF_l8XzGkxKyXuiwwfGbW8HQhmZ0TEMA.xx.GtWD6AzejaHpFLBk05PReA'
    const driver = new AES256GCM({ id: 'lanz', key: SECRET })

    assert.isNull(driver.decrypt(token))
  })

  test('return null when unable to decode tag', ({ assert }) => {
    const token = 'lanz.JFPf0dF5fxMF_l8XzGkxKyXuiwwfGbW8HQhmZ0TEMA.bHgH2t61PsbFIdq4.xx'
    const driver = new AES256GCM({ id: 'lanz', key: SECRET })

    assert.isNull(driver.decrypt(token))
  })

  test('return null when authentication tag is truncated', ({ assert }) => {
    const driver = new AES256GCM({ id: 'lanz', key: SECRET })
    const encrypted = driver.encrypt({ username: 'lanz' })
    const [id, cipherText, iv, tag] = encrypted.split('.')

    assert.isNull(driver.decrypt(`${id}.${cipherText}.${iv}.${tag.slice(0, 6)}`))
  })

  test('return null when an unsigned segment is appended', ({ assert }) => {
    const driver = new AES256GCM({ id: 'lanz', key: SECRET })
    const encrypted = driver.encrypt({ username: 'lanz' })

    assert.isNull(driver.decrypt(`${encrypted}.unsigned`))
  })

  test('bind encrypted values to their encrypter id', ({ assert }) => {
    const source = new AES256GCM({ id: 'source', key: SECRET })
    const target = new AES256GCM({ id: 'target', key: SECRET })
    const [, cipherText, iv, tag] = source.encrypt({ username: 'lanz' }).split('.')

    assert.isNull(target.decrypt(`target.${cipherText}.${iv}.${tag}`))
    assert.isNull(target.decrypt(`target.${cipherText.replace('v1:', '')}.${iv}.${tag}`))
  })

  test('return null when encrypted value is tampered', ({ assert }) => {
    const driver = new AES256GCM({ id: 'lanz', key: SECRET })
    const encrypted = driver.encrypt({ username: 'lanz' })

    assert.isNull(driver.decrypt(encrypted.slice(2)))
  })

  test('return null when iv value is tampered', ({ assert }) => {
    const driver = new AES256GCM({ id: 'lanz', key: SECRET })
    const encrypted = driver.encrypt({ username: 'lanz' })

    const ivIndex = encrypted.indexOf('--') + 2
    const part1 = encrypted.slice(0, ivIndex)
    const part2 = encrypted.slice(ivIndex).slice(2)

    assert.isNull(driver.decrypt(`${part1}${part2}`))
  })

  test('return null when purpose is missing during decrypt', ({ assert }) => {
    const driver = new AES256GCM({ id: 'lanz', key: SECRET })
    const encrypted = driver.encrypt({ username: 'lanz' }, { purpose: 'login' })

    assert.isNull(driver.decrypt(encrypted))
  })

  test('return null when purpose is defined only during decrypt', ({ assert }) => {
    const driver = new AES256GCM({ id: 'lanz', key: SECRET })
    const encrypted = driver.encrypt({ username: 'lanz' })

    assert.isNull(driver.decrypt(encrypted, 'login'))
  })

  test('return null when purpose are not same', ({ assert }) => {
    const driver = new AES256GCM({ id: 'lanz', key: SECRET })
    const encrypted = driver.encrypt({ username: 'lanz' }, { purpose: 'register' })

    assert.isNull(driver.decrypt(encrypted, 'login'))
  })

  test('decrypt when purpose are same', ({ assert }) => {
    const driver = new AES256GCM({ id: 'lanz', key: SECRET })
    const encrypted = driver.encrypt({ username: 'lanz' }, { purpose: 'register' })

    assert.deepEqual(driver.decrypt(encrypted, 'register'), { username: 'lanz' })
  })

  test('encrypt with options object containing both expiresIn and purpose', ({ assert }) => {
    const driver = new AES256GCM({ id: 'lanz', key: SECRET })
    const encrypted = driver.encrypt({ username: 'lanz' }, { expiresIn: '1h', purpose: 'register' })

    assert.deepEqual(driver.decrypt(encrypted, 'register'), { username: 'lanz' })
  })

  test('backward compatibility: encrypt with positional arguments', ({ assert }) => {
    const driver = new AES256GCM({ id: 'lanz', key: SECRET })
    const encrypted = driver.encrypt({ username: 'lanz' }, undefined, 'register')

    assert.deepEqual(driver.decrypt(encrypted, 'register'), { username: 'lanz' })
  })

  test('create deterministic blind index for the same value and purpose', ({ assert }) => {
    const driver = new AES256GCM({ id: 'lanz', key: SECRET })
    const one = driver.blindIndex('foo@example.com', 'users.email')
    const two = driver.blindIndex('foo@example.com', 'users.email')

    assert.equal(one, two)
  })

  test('return different blind index when purpose changes', ({ assert }) => {
    const driver = new AES256GCM({ id: 'lanz', key: SECRET })
    const one = driver.blindIndex('foo@example.com', 'users.email')
    const two = driver.blindIndex('foo@example.com', 'users.login')

    assert.notEqual(one, two)
  })

  test('return blind indexes list', ({ assert }) => {
    const driver = new AES256GCM({ id: 'lanz', key: SECRET })
    const indexes = driver.blindIndexes('foo@example.com', 'users.email')

    assert.lengthOf(indexes, 1)
    assert.equal(indexes[0], driver.blindIndex('foo@example.com', 'users.email'))
  })

  test('fail when blind index purpose is missing', ({ assert }) => {
    const driver = new AES256GCM({ id: 'lanz', key: SECRET })

    assert.throws(
      () => driver.blindIndex('foo@example.com', ''),
      'Blind index requires a non-empty purpose'
    )
  })
})

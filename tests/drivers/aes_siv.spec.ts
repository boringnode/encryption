/*
 * @boringnode/encryption
 *
 * @license MIT
 * @copyright Boring Node
 */

import { test } from '@japa/runner'
import { AESSIV, aessiv } from '../../src/drivers/aes_siv.js'

const SECRET = 'averylongradom32charactersstring'

test.group('AES-SIV', () => {
  test('fail when secret is missing', ({ assert }) => {
    assert.throws(
      // @ts-expect-error
      () => new AESSIV({ key: null }),
      'Missing key. The key is required to encrypt values'
    )
  })

  test('fail when secret is not bigger than 16 chars', ({ assert }) => {
    assert.throws(
      () => new AESSIV({ id: 'lanz', key: 'hello-world' }),
      'The value of your key should be at least 16 characters long'
    )
  })

  test('fail when id is missing', ({ assert }) => {
    assert.throws(
      // @ts-expect-error
      () => new AESSIV({ key: SECRET }),
      'Missing id. The id is required to encrypt values'
    )
  })

  test('fail when id contains separator', ({ assert }) => {
    assert.throws(
      () => new AESSIV({ id: 'lan.z', key: SECRET }),
      'Invalid id. The id must be a non-empty string and cannot contain "."'
    )
  })

  test('fail when id is empty', ({ assert }) => {
    assert.throws(
      () => new AESSIV({ id: '', key: SECRET }),
      'Invalid id. The id must be a non-empty string and cannot contain "."'
    )
  })

  test('accept single key in deterministic driver config', ({ assert }) => {
    const config = aessiv({ id: 'lanz', key: SECRET })
    assert.equal(config.keys.length, 1)
  })

  test('encrypt value', ({ assert }) => {
    const driver = new AESSIV({ id: 'lanz', key: SECRET })

    assert.notEqual(driver.encrypt('hello-world'), 'hello-world')
  })

  test('encrypt an object with a secret', ({ assert }) => {
    const driver = new AESSIV({ id: 'lanz', key: SECRET })
    const encrypted = driver.encrypt({ username: 'lanz' })

    assert.exists(encrypted)
  })

  test('ensure output is deterministic for each encryption call', ({ assert }) => {
    const driver = new AESSIV({ id: 'lanz', key: SECRET })
    const one = driver.encrypt({ username: 'lanz' })
    const two = driver.encrypt({ username: 'lanz' })

    assert.equal(one, two)
  })

  test('ensure output changes when payload changes', ({ assert }) => {
    const driver = new AESSIV({ id: 'lanz', key: SECRET })
    const one = driver.encrypt({ username: 'lanz' })
    const two = driver.encrypt({ username: 'virk' })

    assert.notEqual(one, two)
  })

  test('return null when decrypting non-string values', ({ assert }) => {
    const driver = new AESSIV({ id: 'lanz', key: SECRET })

    // @ts-expect-error
    assert.isNull(driver.decrypt(null))
  })

  test('decrypt encrypted value', ({ assert }) => {
    const driver = new AESSIV({ id: 'lanz', key: SECRET })
    const encrypted = driver.encrypt({ username: 'lanz' })

    assert.deepEqual(driver.decrypt(encrypted), { username: 'lanz' })
  })

  test('return null when decrypting not the same id', ({ assert }) => {
    const driver = new AESSIV({ id: 'lanz', key: SECRET })
    const encrypted = driver.encrypt({ username: 'lanz' })

    const [, cipherText, syntheticIv] = encrypted.split('.')
    assert.isNull(driver.decrypt(`virk.${cipherText}.${syntheticIv}`))
  })

  test('return null when value is in invalid format', ({ assert }) => {
    const driver = new AESSIV({ id: 'lanz', key: SECRET })

    assert.isNull(driver.decrypt('lanz.aes_siv.foo.bar'))
  })

  test('return null when unable to decode encrypted value', ({ assert }) => {
    const driver = new AESSIV({ id: 'lanz', key: SECRET })
    const encrypted = driver.encrypt({ username: 'lanz' })
    const [, , syntheticIv] = encrypted.split('.')

    assert.isNull(driver.decrypt(`lanz.xx.${syntheticIv}`))
  })

  test('return null when unable to decode synthetic iv', ({ assert }) => {
    const driver = new AESSIV({ id: 'lanz', key: SECRET })
    const encrypted = driver.encrypt({ username: 'lanz' })
    const [, cipherText] = encrypted.split('.')

    assert.isNull(driver.decrypt(`lanz.${cipherText}.xx`))
  })

  test('return null when encrypted value is tampered', ({ assert }) => {
    const driver = new AESSIV({ id: 'lanz', key: SECRET })
    const encrypted = driver.encrypt({ username: 'lanz' })
    const [id, cipherText, syntheticIv] = encrypted.split('.')

    assert.isNull(driver.decrypt(`${id}.${cipherText.slice(1)}.${syntheticIv}`))
  })

  test('return null when synthetic iv value is tampered', ({ assert }) => {
    const driver = new AESSIV({ id: 'lanz', key: SECRET })
    const encrypted = driver.encrypt({ username: 'lanz' })
    const [id, cipherText, syntheticIv] = encrypted.split('.')

    assert.isNull(driver.decrypt(`${id}.${cipherText}.${syntheticIv.slice(1)}`))
  })

  test('return null when purpose is missing during decrypt', ({ assert }) => {
    const driver = new AESSIV({ id: 'lanz', key: SECRET })
    const encrypted = driver.encrypt({ username: 'lanz' }, { purpose: 'login' })

    assert.isNull(driver.decrypt(encrypted))
  })

  test('return null when purpose is defined only during decrypt', ({ assert }) => {
    const driver = new AESSIV({ id: 'lanz', key: SECRET })
    const encrypted = driver.encrypt({ username: 'lanz' })

    assert.isNull(driver.decrypt(encrypted, 'login'))
  })

  test('return null when purpose are not same', ({ assert }) => {
    const driver = new AESSIV({ id: 'lanz', key: SECRET })
    const encrypted = driver.encrypt({ username: 'lanz' }, { purpose: 'register' })

    assert.isNull(driver.decrypt(encrypted, 'login'))
  })

  test('decrypt when purpose are same', ({ assert }) => {
    const driver = new AESSIV({ id: 'lanz', key: SECRET })
    const encrypted = driver.encrypt({ username: 'lanz' }, { purpose: 'register' })

    assert.deepEqual(driver.decrypt(encrypted, 'register'), { username: 'lanz' })
  })

  test('encrypt with options object containing purpose', ({ assert }) => {
    const driver = new AESSIV({ id: 'lanz', key: SECRET })
    const encrypted = driver.encrypt({ username: 'lanz' }, { purpose: 'register' })

    assert.deepEqual(driver.decrypt(encrypted, 'register'), { username: 'lanz' })
  })

  test('backward compatibility: encrypt with positional arguments', ({ assert }) => {
    const driver = new AESSIV({ id: 'lanz', key: SECRET })
    const encrypted = driver.encrypt({ username: 'lanz' }, undefined, 'register')

    assert.deepEqual(driver.decrypt(encrypted, 'register'), { username: 'lanz' })
  })

  test('fail when using expiresIn in deterministic mode', ({ assert }) => {
    const driver = new AESSIV({ id: 'lanz', key: SECRET })

    assert.throws(
      () => driver.encrypt({ username: 'lanz' }, { expiresIn: '1h' }),
      'Deterministic encryption does not support expiresIn'
    )
  })

  test('match RFC 5297 A.1 deterministic vector', ({ assert }) => {
    const key = fromHex('fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff')
    const macKey = key.subarray(0, 16)
    const encryptionKey = key.subarray(16)
    const associatedData = [fromHex('101112131415161718191a1b1c1d1e1f2021222324252627')]
    const plainText = fromHex('112233445566778899aabbccddee')
    const expectedSyntheticIv = fromHex('85632d07c6e8f37f950acd320a2ecc93')
    const expectedCipherText = fromHex('40c02b9690c4dc04daef7f6afe5c')

    const encrypted = AESSIV.encryptRaw(macKey, encryptionKey, plainText, associatedData)
    assert.deepEqual(encrypted.syntheticIv, expectedSyntheticIv)
    assert.deepEqual(encrypted.cipherText, expectedCipherText)

    const decrypted = AESSIV.decryptRaw(
      macKey,
      encryptionKey,
      expectedSyntheticIv,
      expectedCipherText,
      associatedData
    )
    assert.deepEqual(decrypted, plainText)
  })

  test('match RFC 5297 A.2 nonce-based vector', ({ assert }) => {
    const key = fromHex('7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f')
    const macKey = key.subarray(0, 16)
    const encryptionKey = key.subarray(16)
    const associatedData = [
      fromHex('00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100'),
      fromHex('102030405060708090a0'),
      fromHex('09f911029d74e35bd84156c5635688c0'),
    ]
    const plainText = fromHex(
      '7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553'
    )
    const expectedSyntheticIv = fromHex('7bdb6e3b432667eb06f4d14bff2fbd0f')
    const expectedCipherText = fromHex(
      'cb900f2fddbe404326601965c889bf17dba77ceb094fa663b7a3f748ba8af829ea64ad544a272e9c485b62a3fd5c0d'
    )

    const encrypted = AESSIV.encryptRaw(macKey, encryptionKey, plainText, associatedData)
    assert.deepEqual(encrypted.syntheticIv, expectedSyntheticIv)
    assert.deepEqual(encrypted.cipherText, expectedCipherText)

    const decrypted = AESSIV.decryptRaw(
      macKey,
      encryptionKey,
      expectedSyntheticIv,
      expectedCipherText,
      associatedData
    )
    assert.deepEqual(decrypted, plainText)
  })
})

function fromHex(value: string): Buffer {
  return Buffer.from(value, 'hex')
}

/*
 * @boringnode/encryption
 *
 * @license MIT
 * @copyright Boring Node
 */

import { test } from '@japa/runner'
import { Encryption } from '../src/encryption.js'
import { ChaCha20Poly1305 } from '../src/drivers/chacha20_poly1305.js'
import { MessageVerifier } from '../src/message_verifier.js'

const SECRET = 'averylongradom32charactersstring'
const SECRET_2 = 'anotherlongradom32characterskey!'

test.group('Encryption', () => {
  test('encrypt and decrypt using the driver', ({ assert }) => {
    const encryption = new Encryption({
      driver: (key) => new ChaCha20Poly1305({ id: 'test', key }),
      keys: [SECRET],
    })

    const encrypted = encryption.encrypt({ username: 'virk' })
    assert.deepEqual(encryption.decrypt(encrypted), { username: 'virk' })
  })

  test('encrypt using the first key', ({ assert }) => {
    const encryption = new Encryption({
      driver: (key) => new ChaCha20Poly1305({ id: 'test', key }),
      keys: [SECRET, SECRET_2],
    })

    const encrypted = encryption.encrypt({ username: 'virk' })

    // Should be decryptable with just the first key
    const singleKeyEncryption = new Encryption({
      driver: (key) => new ChaCha20Poly1305({ id: 'test', key }),
      keys: [SECRET],
    })
    assert.deepEqual(singleKeyEncryption.decrypt(encrypted), { username: 'virk' })
  })

  test('decrypt using any of the keys', ({ assert }) => {
    // Encrypt with the old key
    const oldEncryption = new Encryption({
      driver: (key) => new ChaCha20Poly1305({ id: 'test', key }),
      keys: [SECRET_2],
    })
    const encryptedWithOldKey = oldEncryption.encrypt({ username: 'virk' })

    // New encryption with rotated keys (new key first, old key second)
    const newEncryption = new Encryption({
      driver: (key) => new ChaCha20Poly1305({ id: 'test', key }),
      keys: [SECRET, SECRET_2],
    })

    // Should still be able to decrypt with the old key
    assert.deepEqual(newEncryption.decrypt(encryptedWithOldKey), { username: 'virk' })
  })

  test('return null when none of the keys can decrypt', ({ assert }) => {
    const thirdKey = 'yetanotherlongrandomcharacters!!'

    const unrelatedEncryption = new Encryption({
      driver: (key) => new ChaCha20Poly1305({ id: 'test', key }),
      keys: [thirdKey],
    })
    const encrypted = unrelatedEncryption.encrypt({ username: 'virk' })

    const encryption = new Encryption({
      driver: (key) => new ChaCha20Poly1305({ id: 'test', key }),
      keys: [SECRET, SECRET_2],
    })
    assert.isNull(encryption.decrypt(encrypted))
  })

  test('get message verifier instance', ({ assert }) => {
    const encryption = new Encryption({
      driver: (key) => new ChaCha20Poly1305({ id: 'test', key }),
      keys: [SECRET],
    })

    assert.instanceOf(encryption.getMessageVerifier(), MessageVerifier)
  })

  test('sign using the first key', ({ assert }) => {
    const encryption = new Encryption({
      driver: (key) => new ChaCha20Poly1305({ id: 'test', key }),
      keys: [SECRET, SECRET_2],
    })

    const signed = encryption.getMessageVerifier().sign({ username: 'virk' })

    // Should be unsignable with just the first key
    const singleKeyEncryption = new Encryption({
      driver: (key) => new ChaCha20Poly1305({ id: 'test', key }),
      keys: [SECRET],
    })
    assert.deepEqual(singleKeyEncryption.getMessageVerifier().unsign(signed), { username: 'virk' })
  })

  test('unsign using any of the keys', ({ assert }) => {
    // Sign with the old key
    const oldEncryption = new Encryption({
      driver: (key) => new ChaCha20Poly1305({ id: 'test', key }),
      keys: [SECRET_2],
    })
    const signedWithOldKey = oldEncryption.getMessageVerifier().sign({ username: 'virk' })

    // New encryption with rotated keys
    const newEncryption = new Encryption({
      driver: (key) => new ChaCha20Poly1305({ id: 'test', key }),
      keys: [SECRET, SECRET_2],
    })

    // Should still be able to unsign with the old key
    assert.deepEqual(newEncryption.getMessageVerifier().unsign(signedWithOldKey), {
      username: 'virk',
    })
  })

  test('return null when none of the keys can unsign', ({ assert }) => {
    const thirdKey = 'yetanotherlongrandomcharacters!!'

    const unrelatedEncryption = new Encryption({
      driver: (key) => new ChaCha20Poly1305({ id: 'test', key }),
      keys: [thirdKey],
    })
    const signed = unrelatedEncryption.getMessageVerifier().sign({ username: 'virk' })

    const encryption = new Encryption({
      driver: (key) => new ChaCha20Poly1305({ id: 'test', key }),
      keys: [SECRET, SECRET_2],
    })
    assert.isNull(encryption.getMessageVerifier().unsign(signed))
  })

  test('encrypt with options object containing purpose', ({ assert }) => {
    const encryption = new Encryption({
      driver: (key) => new ChaCha20Poly1305({ id: 'test', key }),
      keys: [SECRET],
    })

    const encrypted = encryption.encrypt({ username: 'virk' }, { purpose: 'test' })
    assert.deepEqual(encryption.decrypt(encrypted, 'test'), { username: 'virk' })
    assert.isNull(encryption.decrypt(encrypted, 'wrong'))
  })

  test('encrypt with options object containing expiresIn and purpose', ({ assert }) => {
    const encryption = new Encryption({
      driver: (key) => new ChaCha20Poly1305({ id: 'test', key }),
      keys: [SECRET],
    })

    const encrypted = encryption.encrypt({ username: 'virk' }, { expiresIn: '1h', purpose: 'test' })
    assert.deepEqual(encryption.decrypt(encrypted, 'test'), { username: 'virk' })
  })
})

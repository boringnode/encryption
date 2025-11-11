import { test } from '@japa/runner'
import { EncryptionManagerFactory } from '../factories/encryption_manager.ts'
import { EncryptionManager } from '../src/encryption_manager.ts'
import { ChaCha20Poly1305 } from '../src/drivers/chacha20_poly1305.ts'

test.group('Encryption manager factory', () => {
  test('create instance of EncryptionManager using factory', async ({ assert }) => {
    const encryption = new EncryptionManagerFactory().create()

    assert.instanceOf(encryption, EncryptionManager)

    const encryptedValue = encryption.use().encrypt('secret')
    const driverInstance = new ChaCha20Poly1305({
      id: 'nova',
      keys: ['averylongradom32charactersstring'],
    })

    assert.equal(driverInstance.decrypt(encryptedValue), 'secret')
  })
})

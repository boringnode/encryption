import { test } from '@japa/runner'
import { EncryptionFactory } from '../factories/encryption.ts'
import { Encryption } from '../src/encryption.ts'
import { chacha20poly1305 } from '../src/drivers/chacha20_poly1305.ts'

test.group('Encryption factory', () => {
  test('create instance of Encryption using factory', async ({ assert }) => {
    const encryption = new EncryptionFactory().create()

    assert.instanceOf(encryption, Encryption)

    const encryptedValue = encryption.encrypt('secret')
    const anotherEncryption = new Encryption(
      chacha20poly1305({
        id: 'nova',
        keys: ['averylongradom32charactersstring'],
      })
    )

    assert.equal(anotherEncryption.decrypt(encryptedValue), 'secret')
  })
})

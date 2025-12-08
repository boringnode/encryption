/*
 * @boringnode/encryption
 *
 * @license MIT
 * @copyright Boring Node
 */

import { Encryption, type EncryptionConfig } from '../src/encryption.ts'
import { chacha20poly1305 } from '../src/drivers/chacha20_poly1305.ts'

export class EncryptionFactory {
  #config: EncryptionConfig

  constructor(config?: EncryptionConfig) {
    this.#config =
      config ||
      chacha20poly1305({
        id: 'nova',
        keys: ['averylongradom32charactersstring'],
      })
  }

  create() {
    return new Encryption(this.#config)
  }
}

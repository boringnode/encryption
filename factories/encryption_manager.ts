/*
 * @boringnode/encryption
 *
 * @license MIT
 * @copyright Boring Node
 */

import { EncryptionManager } from '../src/encryption_manager.ts'
import { ChaCha20Poly1305 } from '../src/drivers/chacha20_poly1305.ts'
import type { ManagerDriverFactory } from '../src/types/main.ts'

type Config<KnownEncryptionDriver extends Record<string, ManagerDriverFactory>> = {
  default?: keyof KnownEncryptionDriver
  list: KnownEncryptionDriver
}

export class EncryptionManagerFactory<
  KnownEncryptionDriver extends Record<string, ManagerDriverFactory> = {
    nova: () => ChaCha20Poly1305
  },
> {
  readonly #config: Config<KnownEncryptionDriver>

  constructor(config?: { default?: keyof KnownEncryptionDriver; list: KnownEncryptionDriver }) {
    this.#config =
      config ||
      ({
        default: 'nova',
        list: {
          nova: () =>
            new ChaCha20Poly1305({
              id: 'nova',
              keys: ['averylongradom32charactersstring'],
            }),
        },
      } as unknown as Config<KnownEncryptionDriver>)
  }

  create() {
    return new EncryptionManager(this.#config)
  }
}

/*
 * @boringnode/encryption
 *
 * @license MIT
 * @copyright Boring Node
 */

import { createError } from '@poppinss/utils'

export const E_INSECURE_ENCRYPTER_KEY = createError(
  'The value of your key should be at least 16 characters long',
  'E_INSECURE_ENCRYPTER_KEY'
)

export const E_MISSING_ENCRYPTER_KEY = createError(
  'Missing key. The key is required to encrypt values',
  'E_MISSING_ENCRYPTER_KEY'
)

export const E_MISSING_ENCRYPTER_ID = createError(
  'Missing id. The id is required to encrypt values',
  'E_MISSING_ENCRYPTER_ID'
)

/*
 * @boringnode/encryption
 *
 * @license MIT
 * @copyright Boring Node
 */

import { createError } from '@poppinss/utils/exception'

export const E_INSECURE_ENCRYPTER_KEY = createError(
  'The value of your key should be at least 16 characters long',
  'E_INSECURE_ENCRYPTER_KEY'
)

export const E_MISSING_ENCRYPTER_KEY = createError(
  'Missing key. The key is required to encrypt values',
  'E_MISSING_ENCRYPTER_KEY'
)

export const E_MISSING_ENCRYPTER_KEYS = createError(
  'Missing keys. At least one key is required to encrypt values',
  'E_MISSING_ENCRYPTER_KEYS'
)

export const E_MISSING_ENCRYPTER_ID = createError(
  'Missing id. The id is required to encrypt values',
  'E_MISSING_ENCRYPTER_ID'
)

export const E_INVALID_ENCRYPTER_ID = createError(
  'Invalid id. The id must be a non-empty string and cannot contain "."',
  'E_INVALID_ENCRYPTER_ID'
)

export const E_DETERMINISTIC_DRIVER_EXPIRES_IN_NOT_SUPPORTED = createError(
  'Deterministic encryption does not support expiresIn',
  'E_DETERMINISTIC_DRIVER_EXPIRES_IN_NOT_SUPPORTED'
)

export const E_BLIND_INDEX_PURPOSE_REQUIRED = createError(
  'Blind index requires a non-empty purpose',
  'E_BLIND_INDEX_PURPOSE_REQUIRED'
)

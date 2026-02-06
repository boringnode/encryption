# @boringnode/encryption

<div align="center">

[![typescript-image]][typescript-url]
[![gh-workflow-image]][gh-workflow-url]
[![npm-image]][npm-url]
[![npm-download-image]][npm-download-url]
[![license-image]][license-url]

</div>

A framework-agnostic encryption library for Node.js. Built with simplicity and security in mind, `@boringnode/encryption` provides a unified API for encrypting and signing data with support for multiple encryption algorithms and key rotation.

## Installation

```bash
npm install @boringnode/encryption
```

## Features

- **Multiple Algorithms**: ChaCha20-Poly1305, AES-256-GCM, AES-256-CBC, AES-SIV
- **Key Rotation**: Encrypt with new keys, decrypt with old ones
- **Deterministic Encryption**: AES-SIV driver for equality queries
- **Purpose-Bound Encryption**: Ensure encrypted values are used for their intended purpose
- **Expiration Support**: Set time-to-live on encrypted values
- **Blind Indexes**: Deterministic indexes for equality queries
- **Message Verification**: Sign data without encrypting (HMAC-based)
- **Type-Safe**: Full TypeScript support with typed payloads

## Quick Start

### 1. Configure Encryption

```typescript
import { Encryption } from '@boringnode/encryption'
import { chacha20poly1305 } from '@boringnode/encryption/drivers/chacha20_poly1305'

const encryption = new Encryption(
  chacha20poly1305({
    id: 'app',
    keys: [process.env.APP_KEY],
  })
)
```

`id` must be a non-empty string and cannot contain `.`.

### 2. Encrypt & Decrypt

```typescript
// Encrypt any value
const encrypted = encryption.encrypt({ userId: 1, role: 'admin' })
// => "app.base64EncodedCipherText.base64EncodedIv.base64EncodedTag"

// Decrypt the value
const decrypted = encryption.decrypt(encrypted)
// => { userId: 1, role: 'admin' }
```

## Supported Data Types

The library supports encrypting a wide range of data types:

- Strings
- Numbers
- Booleans
- Arrays
- Objects
- Dates

## Encryption Drivers

### ChaCha20-Poly1305 (recommended)

Modern, fast, and secure. Recommended for most use cases.

```typescript
import { chacha20poly1305 } from '@boringnode/encryption/drivers/chacha20_poly1305'

const config = chacha20poly1305({
  id: 'app',
  keys: ['your-32-character-secret-key-here'],
})
```

### AES-256-GCM

Industry-standard authenticated encryption.

```typescript
import { aes256gcm } from '@boringnode/encryption/drivers/aes_256_gcm'

const config = aes256gcm({
  id: 'app',
  keys: ['your-32-character-secret-key-here'],
})
```

### AES-256-CBC

Legacy support with HMAC authentication.

```typescript
import { aes256cbc } from '@boringnode/encryption/drivers/aes_256_cbc'

const config = aes256cbc({
  id: 'app',
  keys: ['your-32-character-secret-key-here'],
})
```

### AES-SIV (deterministic)

Deterministic encryption for direct equality lookups on encrypted columns.

```typescript
import { aessiv } from '@boringnode/encryption/drivers/aes_siv'

const config = aessiv({
  id: 'app',
  key: 'your-32-character-secret-key-here',
})
```

Notes:

- `expiresIn` is not supported with deterministic encryption.
- Key rotation is not automatic for deterministic ciphertexts. Use an explicit migration/backfill strategy.

## Key Rotation

The library supports multiple keys for seamless key rotation. The first key is used for encryption, while all keys are tried during decryption.

```typescript
const encryption = new Encryption(
  chacha20poly1305({
    id: 'app',
    keys: [
      process.env.NEW_APP_KEY, // Used for encryption
      process.env.OLD_APP_KEY, // Still valid for decryption
    ],
  })
)

// New encryptions use NEW_APP_KEY
const encrypted = encryption.encrypt('secret')

// Decryption works with both keys
encryption.decrypt(encryptedWithOldKey) // Works
encryption.decrypt(encryptedWithNewKey) // Works
```

## Purpose-Bound Encryption

Ensure encrypted values are only used for their intended purpose:

```typescript
// Encrypt with a purpose
const token = encryption.encrypt({ userId: 1 }, undefined, 'password-reset')

// Must provide same purpose to decrypt
encryption.decrypt(token, 'password-reset') // => { userId: 1 }
encryption.decrypt(token, 'email-verify')   // => null
encryption.decrypt(token)                    // => null
```

## Expiration Support

Set a time-to-live on encrypted values:

```typescript
// Expires in 1 hour
const token = encryption.encrypt({ userId: 1 }, '1h')

// Expires in 30 minutes
const token = encryption.encrypt({ userId: 1 }, '30m')

// Expires in 7 days
const token = encryption.encrypt({ userId: 1 }, '7d')

// After expiration, decrypt returns null
encryption.decrypt(expiredToken) // => null
```

## Blind Indexes

Blind indexes are deterministic hashes used for equality queries:

```typescript
const index = encryption.blindIndex('foo@example.com', 'users.email')
```

When rotating keys, query using all blind indexes:

```typescript
const indexes = encryption.blindIndexes('foo@example.com', 'users.email')
// Use SQL: WHERE email_index IN (...)
```

Rules:

- `purpose` is required and should identify the field/context (`users.email`, `users.ssn`, ...).
- Matching is exact-bytes (no implicit normalization).
- Prefer normalized primitive values for blind indexes (`string`/`number`/`boolean`/ISO date).
- For structured objects, normalize/canonicalize before indexing (for example, map object -> stable string yourself).

```typescript
const emailIndex = encryption.blindIndex(email.trim().toLowerCase(), 'users.email')
```

## Message Verifier

When you need to ensure data integrity without hiding the content, use the `MessageVerifier`. The payload is base64-encoded (not encrypted) and signed with HMAC.

```typescript
import { MessageVerifier } from '@boringnode/encryption/message_verifier'

const verifier = new MessageVerifier(['your-secret-key'])

// Sign a value
const signed = verifier.sign({ userId: 1 })

// Verify and retrieve the value
const payload = verifier.unsign(signed)
// => { userId: 1 }

// Tampered values return null
verifier.unsign('tampered.value') // => null
```

The verifier also supports purpose and expiration:

```typescript
// With expiration
const signed = verifier.sign({ userId: 1 }, '1h')

// With purpose
const signed = verifier.sign({ userId: 1 }, undefined, 'api-token')
const payload = verifier.unsign(signed, 'api-token')
```

## Base64 Utilities

URL-safe base64 encoding/decoding utilities are available:

```typescript
import { base64UrlEncode, base64UrlDecode } from '@boringnode/encryption/base64'

const encoded = base64UrlEncode('Hello World')
const decoded = base64UrlDecode(encoded, 'utf8')
```

## HMAC

Generate and verify HMAC signatures:

```typescript
import { Hmac } from '@boringnode/encryption'

const hmac = new Hmac(secretKey)

// Generate HMAC
const hash = hmac.generate('data to sign')

// Verify HMAC (timing-safe comparison)
const isValid = hmac.compare('data to sign', hash)
```

## Error Handling

The library is designed to return `null` on decryption failures rather than throwing exceptions. This prevents timing attacks and simplifies error handling:

```typescript
const result = encryption.decrypt(maybeInvalidValue)

if (result === null) {
  // Invalid, expired, wrong purpose, or tampered
}
```

[gh-workflow-image]: https://img.shields.io/github/actions/workflow/status/boringnode/encryption/checks.yml?branch=0.x&style=for-the-badge
[gh-workflow-url]: https://github.com/boringnode/encryption/actions/workflows/checks.yml
[npm-image]: https://img.shields.io/npm/v/@boringnode/encryption.svg?style=for-the-badge&logo=npm
[npm-url]: https://www.npmjs.com/package/@boringnode/encryption
[npm-download-image]: https://img.shields.io/npm/dm/@boringnode/encryption?style=for-the-badge
[npm-download-url]: https://www.npmjs.com/package/@boringnode/encryption
[typescript-image]: https://img.shields.io/badge/Typescript-294E80.svg?style=for-the-badge&logo=typescript
[typescript-url]: https://www.typescriptlang.org
[license-image]: https://img.shields.io/npm/l/@boringnode/encryption?color=blueviolet&style=for-the-badge
[license-url]: LICENSE.md

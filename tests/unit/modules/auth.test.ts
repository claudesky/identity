import { describe, expect, it, jest } from '@jest/globals'
import { Auth, InvalidTokenException } from '../../../src/modules/auth-module'
import { privateEncrypt, publicDecrypt, randomUUID } from 'crypto'
import * as fs from 'fs/promises'
import { dirname } from 'path'
import { after } from 'node:test'
import {
  FileNotExistException,
  NotReadyException,
  UndefinedAttributeException,
} from '../../../src/modules/exceptions'
import { JwtPayload, verify } from 'jsonwebtoken'
import { MockException } from '../test-utils'

import { tokenRepositoryService } from '../../../src/services/token-repository-service'

jest.mock('fs/promises', () => {
  return {
    __esModule: true,
    ...(jest.requireActual('fs/promises') as object),
  }
})

const passphrase = (process.env.APP_JWT_PASSPHRASE = 'test')

const tmpPath = 'tests/tmp/auth'
after(async () => {
  await fs.rm(`${tmpPath}`, { recursive: true, force: true })
})

const encryptDecrypt = (testString: string, authModule: Auth) => {
  const encryptedString = encrypt(testString, authModule)
  const decryptedString = decrypt(encryptedString, authModule)

  return decryptedString
}

const encrypt = (testString: string, authModule: Auth) => {
  const key = authModule.privateKey

  return privateEncrypt(key, Buffer.from(testString)).toString('base64')
}

const decrypt = (encryptedString: string, authModule: Auth) => {
  const key = authModule.publicKey

  return publicDecrypt(key, Buffer.from(encryptedString, 'base64')).toString()
}

describe('without filesystem', () => {
  const authModule = new Auth(tokenRepositoryService)
  it('creates working temporary keys', async () => {
    await authModule.ready

    const testString = 'testing'
    const decryptedString = encryptDecrypt(testString, authModule)

    expect(testString).toEqual(decryptedString)
  })

  it('throws error if accessing undefined private key', async () => {
    await authModule.ready

    authModule.clearPrivateKey()
    expect(() => authModule.privateKey).toThrow(UndefinedAttributeException)
  })
})

describe('readiness', () => {
  it('cannot access property when not ready', async () => {
    const authModule = new Auth(tokenRepositoryService, {
      publicKeyPath: 'test',
    })
    expect(() => authModule.publicKey).toThrow(NotReadyException)
    await expect(authModule.ready).rejects.toThrow(FileNotExistException)
  })
})

describe('public key regeneration', () => {
  it('creates working public key from existing private key', async () => {
    const generatorModule = new Auth(tokenRepositoryService)
    await generatorModule.ready

    const privateKey = generatorModule.privateKey

    const privateKeyPath = `${tmpPath}/${randomUUID()}/privateKey.pem`
    await fs.mkdir(dirname(privateKeyPath), { recursive: true })
    await fs.writeFile(
      privateKeyPath,
      privateKey.export({
        type: 'pkcs8',
        format: 'pem',
        cipher: 'aes-256-cbc',
        passphrase,
      })
    )

    const authModule = new Auth(tokenRepositoryService, { privateKeyPath })
    await authModule.ready

    const testString = 'testing 2'
    const decryptedString = encryptDecrypt(testString, authModule)

    expect(testString).toEqual(decryptedString)
  })
})

describe('public key only', () => {
  it('able to decrypt without private key', async () => {
    const keyPath = `${tmpPath}/${randomUUID()}`
    const encryptor = new Auth(tokenRepositoryService, {
      generatePath: keyPath,
    })
    await encryptor.ready
    const decryptor = new Auth(tokenRepositoryService, {
      publicKeyPath: encryptor.publicKeyPath,
    })
    await decryptor.ready

    const testString = 'testing 3'

    const encryptedString = encrypt(testString, encryptor)
    const decryptedString = decrypt(encryptedString, decryptor)

    expect(testString).toEqual(decryptedString)
  })
})

describe('passphrase', () => {
  it('can use blank passphrase', async () => {
    delete process.env.APP_JWT_PASSPHRASE

    const keyPath = `${tmpPath}/${randomUUID()}`
    const encryptor = new Auth(tokenRepositoryService, {
      generatePath: keyPath,
    })
    await encryptor.ready
    const decryptor = new Auth(tokenRepositoryService, {
      publicKeyPath: encryptor.publicKeyPath,
    })
    await decryptor.ready

    const testString = 'testing 4'

    const encryptedString = encrypt(testString, encryptor)
    const decryptedString = decrypt(encryptedString, decryptor)

    expect(testString).toEqual(decryptedString)

    process.env.APP_JWT_PASSPHRASE = passphrase
  })
})

describe('key loading', () => {
  it('can load public and private keys from path', async () => {
    const keyPath = `${tmpPath}/${randomUUID()}`
    const auth1 = new Auth(tokenRepositoryService, { generatePath: keyPath })
    await auth1.ready
    const auth2 = new Auth(tokenRepositoryService, {
      publicKeyPath: auth1.publicKeyPath,
      privateKeyPath: (auth1 as any)._privateKeyPath,
    })
    await auth2.ready

    const testString = 'testing 5'

    let encryptedString = encrypt(testString, auth1)
    let decryptedString = decrypt(encryptedString, auth2)

    expect(testString).toEqual(decryptedString)

    encryptedString = encrypt(testString, auth2)
    decryptedString = decrypt(encryptedString, auth1)

    expect(testString).toEqual(decryptedString)
  })
})

describe('key writing', () => {
  it('can write to public key to path without private keys', async () => {
    const keyPath = `${tmpPath}/${randomUUID()}`
    const newKeyPath = `${tmpPath}/${randomUUID()}`
    const encryptor = new Auth(tokenRepositoryService, {
      generatePath: keyPath,
    })
    await encryptor.ready
    const decryptor = new Auth(tokenRepositoryService, {
      publicKeyPath: encryptor.publicKeyPath,
      generatePath: newKeyPath,
    })
    await decryptor.ready

    const testString = 'testing 6'

    const encryptedString = encrypt(testString, encryptor)
    const decryptedString = decrypt(encryptedString, decryptor)

    expect(testString).toEqual(decryptedString)
  })

  it('can overwrite existing keys', async () => {
    const keyPath = `${tmpPath}/${randomUUID()}`
    const encryptor = new Auth(tokenRepositoryService, {
      generatePath: keyPath,
    })
    await encryptor.ready
    const decryptor = new Auth(tokenRepositoryService, {
      privateKeyPath: (encryptor as any)._privateKeyPath,
      generatePath: keyPath,
      overwrite: true,
    })
    await decryptor.ready

    const testString = 'testing 7'

    const encryptedString = encrypt(testString, encryptor)
    const decryptedString = decrypt(encryptedString, decryptor)

    expect(testString).toEqual(decryptedString)
  })
})

describe('JWT creation', () => {
  it('creates JWT', async () => {
    const authModule = new Auth(tokenRepositoryService)
    await authModule.ready

    const subject = 'user-id-1'

    const JWT = authModule.createJWT(subject)

    const decoded = verify(JWT, authModule.publicKey, {}) as JwtPayload

    expect(decoded.sub).toEqual(subject)
  })
})

describe('JWT verification', () => {
  it('verifies JWT', async () => {
    const keyPath = `${tmpPath}/${randomUUID()}`
    const auth1 = new Auth(tokenRepositoryService, { generatePath: keyPath })
    await auth1.ready
    const auth2 = new Auth(tokenRepositoryService, {
      publicKeyPath: auth1.publicKeyPath,
    })
    await auth2.ready

    const subject = 'user-id-2'

    const JWT = auth1.createJWT(subject)

    const decoded = auth2.decryptJWT(JWT)

    expect(decoded.sub).toEqual(subject)
  })

  it('verifies JWT with newly generated pubkey', async () => {
    const keyPath = `${tmpPath}/${randomUUID()}`
    const auth1 = new Auth(tokenRepositoryService, { generatePath: keyPath })
    await auth1.ready
    const auth2 = new Auth(tokenRepositoryService, {
      privateKeyPath: (auth1 as any)._privateKeyPath,
    })
    await auth2.ready

    const subject = 'user-id-3'

    const JWT = auth1.createJWT(subject)

    const decoded = auth2.decryptJWT(JWT)

    expect(decoded.sub).toEqual(subject)
  })
})

describe('refresh tokens', () => {
  it('can issue a new token with refresh token', async () => {
    const authModule = new Auth(tokenRepositoryService)
    await authModule.ready

    const subject = 'user-id-4'

    const tokenResult = await authModule.newToken(subject)

    const refreshToken = authModule.decryptJWT(tokenResult.refreshToken)

    const refreshResult = await authModule.refreshToken(
      tokenResult.refreshToken
    )

    const refreshTokenResult = authModule.decryptJWT(refreshResult.refreshToken)

    const authTokenResult = authModule.decryptJWT(refreshResult.accessToken)

    // New refresh token's family should match inital refresh token's id
    expect(refreshTokenResult.jtf).toEqual(refreshToken.jti)

    // Access token's family should match initial refresh token's id
    expect(authTokenResult.jtf).toEqual(refreshToken.jti)

    // Access token's parent should match the new refresh token's id
    expect(authTokenResult.jtp).toEqual(refreshTokenResult.jti)
  })

  it('rejects invalid refresh tokens', async () => {
    const authModule = new Auth(tokenRepositoryService)
    await authModule.ready

    const invalidToken1 = authModule.createJWT('test')

    await expect(authModule.refreshToken(invalidToken1)).rejects.toThrow(
      InvalidTokenException
    )

    await expect(authModule.terminateToken(invalidToken1)).rejects.toThrow(
      InvalidTokenException
    )

    const invalidToken2 = authModule.createJWT(
      'test2',
      { jtf: 'invalid1' },
      'invalid2'
    )

    await expect(authModule.refreshToken(invalidToken2)).rejects.toThrow(
      InvalidTokenException
    )

    await expect(authModule.terminateToken(invalidToken2)).rejects.toThrow(
      InvalidTokenException
    )

    const invalidToken3 = authModule.createJWT(
      'test3',
      { jtf: randomUUID() },
      randomUUID()
    )

    await expect(authModule.refreshToken(invalidToken3)).rejects.toThrow(
      InvalidTokenException
    )

    await expect(authModule.terminateToken(invalidToken3)).rejects.toThrow(
      InvalidTokenException
    )
  })

  it('prevents replay attack', async () => {
    const authModule = new Auth(tokenRepositoryService)
    await authModule.ready

    const tokens = await authModule.newToken('test')

    await authModule.refreshToken(tokens.refreshToken)

    await expect(authModule.refreshToken(tokens.refreshToken)).rejects.toThrow(
      InvalidTokenException
    )
  })

  it('can no longer use refresh token after logout', async () => {
    const authModule = new Auth(tokenRepositoryService)
    await authModule.ready

    const tokens = await authModule.newToken('test')

    await authModule.terminateToken(tokens.refreshToken)

    await expect(authModule.refreshToken(tokens.refreshToken)).rejects.toThrow(
      InvalidTokenException
    )
  })
})

describe('filesystem unhandled error', () => {
  it('throws unhandled errors', async () => {
    const mock = jest.spyOn(fs, 'readFile')
    mock.mockImplementationOnce(() => {
      throw new MockException()
    })

    const authModule = new Auth(tokenRepositoryService, {
      publicKeyPath: 'test',
    })
    expect(() => authModule.publicKey).toThrow(NotReadyException)
    await expect(authModule.ready).rejects.toThrow(MockException)
  })
})

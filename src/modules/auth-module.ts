/**
 * Auth Module
 * This module handles authentication. Its primary functions are:
 * - Keypair Generation
 * - Key Storage and Retreival
 * - Token Creation
 * - Refresh Token Handling
 */

import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  KeyObject,
  randomUUID,
  UUID,
} from 'crypto'
import { JwtPayload, sign, verify } from 'jsonwebtoken'
import {
  FileNotExistException,
  NotImplementedException,
  NotReadyException,
  UndefinedAttributeException,
  UnexpectedException,
} from './exceptions'
import { logger } from '../services/logger'
import { existsSync } from 'fs'
import { dirname } from 'path'
import { ITokenRepository } from '../repositories/token/itoken-repository'
import { mkdir, readFile, rename, writeFile } from 'fs/promises'

type RefreshTokenResult = {
  refreshToken: string
  accessToken: string
}

type AuthModuleOptions = {
  publicKeyPath?: string
  privateKeyPath?: string
  generatePath?: string
  overwrite?: boolean
}

export class InvalidTokenException extends Error {
  name = 'InvalidTokenException'
  constructor() {
    super('The provided token was invalid')
  }
}

const regexValidator =
  /^[0-9a-fA-F]{8}\b/.source +
  /-[0-9a-fA-F]{4}\b/.source +
  /-[0-9a-fA-F]{4}\b/.source +
  /-[0-9a-fA-F]{4}\b/.source +
  /-[0-9a-fA-F]{12}$/.source

export class Auth {
  public ready: Promise<boolean>
  private _privateKeyPath: string | undefined
  private _publicKeyPath: string | undefined
  private _privateKey: KeyObject | undefined
  private _publicKey: string | undefined
  private _passphrase: string = process.env.APP_JWT_PASSPHRASE ?? ''
  private _tokenRepository: ITokenRepository

  public get publicKey(): string {
    if (this._publicKey === undefined) throw new NotReadyException()
    return this._publicKey
  }

  public set publicKey(key: string | Buffer) {
    if (typeof key === 'string') {
      this._publicKey = key
    } else if (key instanceof Buffer) {
      this._publicKey = key.toString()
    }
  }

  public get privateKey(): KeyObject {
    if (this._privateKey == undefined) throw new UndefinedAttributeException()
    return this._privateKey
  }

  public set privateKey(key: string | Buffer | KeyObject) {
    if (typeof key === 'string') {
      this._privateKey = createPrivateKey({
        key: Buffer.from(key),
        passphrase: this._passphrase,
      })
    } else if (key instanceof Buffer) {
      this._privateKey = createPrivateKey({
        key,
        passphrase: this._passphrase,
      })
    }
  }

  public clearPrivateKey() {
    this._privateKey = undefined
    this._privateKeyPath = undefined
  }

  public get publicKeyPath(): string | undefined {
    return this._publicKeyPath
  }

  constructor(
    tokenRepository: ITokenRepository,
    authModuleOptions: AuthModuleOptions = {}
  ) {
    const options = Object.assign({ overwrite: false }, authModuleOptions)
    this._tokenRepository = tokenRepository

    this._privateKeyPath = options.privateKeyPath
    this._publicKeyPath = options.publicKeyPath

    this.ready = Promise.all([
      this.init(
        options.publicKeyPath,
        options.privateKeyPath,
        options.generatePath,
        options.overwrite
      ),
      this._tokenRepository.ready,
    ]).then((_) => true)
  }

  private async init(
    publicKeyPath: string | undefined,
    privateKeyPath: string | undefined,
    generatePath: string | undefined,
    overwrite: boolean
  ) {
    // prettier-ignore
    if (publicKeyPath === undefined && privateKeyPath === undefined) {
      // No keypaths defined create temporary keys
      const keyPair = this.generateKeys()
      this.privateKey = keyPair.privateKey
      this.publicKey = keyPair.publicKey
      this._publicKey = this.publicKey
    }
    else if (publicKeyPath === undefined && privateKeyPath !== undefined) {
      // There is a private key, but no public key
      // Generate a new public key
      this.privateKey = await this.fetchKeyFromPath(privateKeyPath)
      this.publicKey = this.generatePublicKey(this.privateKey)
      this._publicKey = this.publicKey
    }
    else if (publicKeyPath !== undefined && privateKeyPath === undefined) {
      // There is a public key but no private key
      // module is in read and verify-only mode
      // We cannot sign new JWTs
      this.publicKey = await this.fetchKeyFromPath(publicKeyPath)
      this._publicKey = this.publicKey

    } else
    /* istanbul ignore else */
    if (publicKeyPath !== undefined && privateKeyPath !== undefined) {
      // Both public and private key paths are set
      // Load the keys from these paths
      this.privateKey = await this.fetchKeyFromPath(privateKeyPath)
      this.publicKey = await this.fetchKeyFromPath(publicKeyPath)
      this._publicKey = this.publicKey
    } else {
      // How could this happen?
      throw new UnexpectedException()
    }

    // write keys to files if generatePath is defined
    if (generatePath !== undefined) {
      await this.writeKeys(
        privateKeyPath,
        publicKeyPath,
        generatePath,
        this.exportPrivateKey(),
        this.publicKey,
        overwrite
      )
    }

    return true
  }

  // Creates a new keypair
  generateKeys() {
    const passphrase = this._passphrase
    const keyPair = generateKeyPairSync('rsa', {
      modulusLength: 4096,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem',
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem',
        cipher: 'aes-256-cbc',
        passphrase,
      },
    })

    return keyPair
  }

  // Generates a public key from an existing private key
  generatePublicKey(privateKey: KeyObject): string {
    return createPublicKey(privateKey).export({
      type: 'spki',
      format: 'pem',
    }) as string // [format: pem] results in string
  }

  exportPrivateKey(): string | undefined {
    if (this._privateKey === undefined) return undefined
    return this.privateKey.export({
      type: 'pkcs8',
      format: 'pem',
      cipher: 'aes-256-cbc',
      passphrase: this._passphrase,
    }) as string
  }

  // Fetches the key from a file at the given path
  async fetchKeyFromPath(path: string): Promise<Buffer> {
    try {
      return await readFile(path)
    } catch (e: any) {
      if (e.code == 'ENOENT') {
        throw new FileNotExistException(path)
      } else {
        throw e
      }
    }
  }

  async writeKeys(
    privateKeyPath: string | undefined,
    publicKeyPath: string | undefined,
    generatePath: string,
    privateKey: string | undefined,
    publicKey: string,
    overwrite: boolean
  ) {
    // Path generation, if any paths are undefined, generate
    // keys at generatePath location
    const newPrivateKeyPath = `${generatePath}/privateKey.pem`
    const newPublicKeyPath = `${generatePath}/publicKey.pem`
    if (privateKeyPath === undefined && privateKey !== undefined) {
      this._privateKeyPath = newPrivateKeyPath
      await this.writeKey(this._privateKeyPath, privateKey, overwrite)
    }
    if (publicKeyPath === undefined) {
      this._publicKeyPath = newPublicKeyPath
      await this.writeKey(this._publicKeyPath, publicKey, overwrite)
    }
  }

  async writeKey(path: string, key: string, overwrite: boolean) {
    const fileExists = await new Promise((resolve) => resolve(existsSync(path)))
    // only write if either the file doesn't exist or we can overwrite
    if (!fileExists || overwrite) {
      await mkdir(dirname(path), { recursive: true })
      if (fileExists) {
        logger.warn(`replacing an existing key at ${path}`)
        await rename(path, `${path}.${new Date().toISOString()}.old`)
      }
      await writeFile(path, key)
    }
  }

  createJWT(
    subject: string,
    payload: object = {},
    jwtid: string = randomUUID(),
    expiresIn: number = 60 * 5 // 5 minutes default
  ): string {
    return sign(payload, this.privateKey, {
      algorithm: 'RS256',
      expiresIn,
      subject,
      jwtid,
    })
  }

  decryptJWT(jwt: string): JwtPayload {
    return verify(jwt, this.publicKey, {}) as JwtPayload
  }

  async verify(): Promise<JwtPayload> {
    // TODO: More verification
    throw new NotImplementedException()
  }

  async newToken(subject: string): Promise<RefreshTokenResult> {
    const familyId = randomUUID()
    const accessToken = this.createJWT(subject, {
      jtf: familyId,
      jtp: familyId,
    })
    const refreshToken = this.createJWT(
      subject,
      { jtf: familyId },
      familyId,
      60 * 60 * 48 // 2 days
    )

    await this._tokenRepository.add(familyId, subject)

    return {
      refreshToken,
      accessToken,
    }
  }

  async refreshToken(refreshToken: string): Promise<RefreshTokenResult> {
    const tokenData = this.decryptJWT(refreshToken)

    const familyId = tokenData.jtf as string | undefined
    const oldId = tokenData.jti
    const subject = tokenData.sub
    const newId = randomUUID()

    if (familyId === undefined || oldId === undefined || subject === undefined)
      throw new InvalidTokenException()

    if (!familyId.match(regexValidator) || !oldId.match(regexValidator))
      throw new InvalidTokenException()

    const familyUUID = familyId as UUID
    const oldUUID = oldId as UUID

    try {
      await this._tokenRepository.reissue(familyUUID, oldUUID, subject, newId)
    } catch (InvalidLastIssuedException) {
      throw new InvalidTokenException()
    }

    const newRefreshToken = this.createJWT(subject, { jtf: familyId }, newId)
    const accessToken = this.createJWT(subject, {
      jtf: familyId,
      jtp: newId,
    })

    return {
      refreshToken: newRefreshToken,
      accessToken,
    }
  }

  async terminateToken(refreshToken: string): Promise<void> {
    const tokenData = this.decryptJWT(refreshToken)

    const familyId = tokenData.jtf as string | undefined

    if (familyId === undefined || !familyId.match(regexValidator))
      throw new InvalidTokenException()

    const familyUUID = familyId as UUID

    try {
      await this._tokenRepository.delete(familyUUID)
    } catch (InvalidLastIssuedException) {
      throw new InvalidTokenException()
    }
  }
}

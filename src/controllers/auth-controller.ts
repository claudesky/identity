import { Request, Response } from 'express'
import {
  NotImplementedException,
  UnexpectedException,
} from '../modules/exceptions'
import { Auth } from '../modules/auth-module'
import { IUserRepository, User } from '../repositories/user/iuser-repository'
import { hash, verify } from 'argon2'

type RegisterRequest = {
  email?: string
  phone_number?: string
  password: string
  name: string
}

type LoginRequest = {
  email?: string
  phone_number?: string
  password: string
}

function validateRegisterRequest(req: Request): RegisterRequest {
  const email = req.body.email as unknown
  const phone_number = req.body.phone_number as unknown
  const password = req.body.password as unknown
  const name = req.body.name as unknown

  // TODO: Install or create a validation library
  // PLACEHOLDER FOR BETTER VALIDATION
  if (
    (typeof email !== 'string' && typeof phone_number !== 'string') ||
    !(typeof email === 'string' || typeof email === 'undefined') ||
    !(
      typeof phone_number === 'string' || typeof phone_number === 'undefined'
    ) ||
    typeof password !== 'string' ||
    typeof name !== 'string'
  ) {
    throw new Error('PLACEHOLDER: Validation Error')
  }

  return {
    email,
    phone_number,
    password,
    name,
  }
}

function validateLoginRequest(req: Request): LoginRequest {
  const email = req.body.email as unknown
  const phone_number = req.body.phone_number as unknown
  const password = req.body.password as unknown

  // TODO: Install or create a validation library
  // PLACEHOLDER FOR BETTER VALIDATION
  if (
    (typeof email !== 'string' && typeof phone_number !== 'string') ||
    !(typeof email === 'string' || typeof email === 'undefined') ||
    !(
      typeof phone_number === 'string' || typeof phone_number === 'undefined'
    ) ||
    typeof password !== 'string'
  ) {
    throw new Error('PLACEHOLDER: Validation Error')
  }

  return {
    email,
    phone_number,
    password,
  }
}

export class AuthController {
  ready: Promise<boolean>
  private _auth: Auth
  private _userRepository: IUserRepository

  constructor(authService: Auth, userRepositoryService: IUserRepository) {
    this._auth = authService
    this._userRepository = userRepositoryService
    this.ready = Promise.all([
      authService.ready,
      userRepositoryService.ready,
    ]).then(() => true)
  }

  async register(req: Request, res: Response) {
    const request = validateRegisterRequest(req)

    let user: User

    if (typeof request.email === 'string') {
      user = await this._userRepository.registerByEmail({
        email: request.email,
        name: request.name,
        password: await hash(request.password),
        phone_number: request.phone_number,
      })
    } else if (typeof request.phone_number === 'string') {
      user = await this._userRepository.registerByPhoneNumber({
        email: request.email,
        name: request.name,
        password: await hash(request.password),
        phone_number: request.phone_number,
      })
    } else {
      throw new UnexpectedException()
    }

    res.send({ user })
  }

  async login(req: Request, res: Response) {
    const request = validateLoginRequest(req)

    let user: User

    if (typeof request.email === 'string') {
      user = await this._userRepository.getUserByEmail(request.email)
    } else if (typeof request.phone_number === 'string') {
      user = await this._userRepository.getUserByPhoneNumber(
        request.phone_number
      )
    } else {
      throw new UnexpectedException()
    }

    if (!await verify(user.password, request.password))
      throw new Error('PLACEHOLDER: Invalid credentials')

    const tokenResult = await this._auth.newToken(user.id)

    res.send({ user, ...tokenResult })
  }

  async verify(req: Request, res: Response) {
    throw new NotImplementedException()
  }

  async refresh(req: Request, res: Response) {}

  async logout(req: Request, res: Response) {
    throw new NotImplementedException()
  }
}

import { describe, expect, it } from '@jest/globals'
import { AuthController } from '../../../src/controllers/auth-controller'
import { createRequest, createResponse } from 'node-mocks-http'
import { authService } from '../../../src/services/auth-service'
import { userRepositoryService } from '../../../src/services/user-repository-service'

const authController = new AuthController(authService, userRepositoryService)

const uuidRegexValidator =
  /^[0-9a-fA-F]{8}\b/.source +
  /-[0-9a-fA-F]{4}\b/.source +
  /-[0-9a-fA-F]{4}\b/.source +
  /-[0-9a-fA-F]{4}\b/.source +
  /-[0-9a-fA-F]{12}$/.source

const jwtRegexValidator = /^[A-Za-z0-9_-]{2,}(?:\.[A-Za-z0-9_-]{2,}){2}$/

const testEmail = 'user@localhost'
const testPassword = 'password'

const register = () => {
  let req = createRequest({
    body: {
      email: testEmail,
      password: testPassword,
      name: 'user',
    },
  })

  let res = createResponse()

  return authController.register(req, res).then(_ => ({req,res}))
}

describe('happy path', () => {
  it('can register and login by email', async () => {
    await authController.ready

    let {req, res} = await register()

    expect(res._getData()).toMatchObject({
      user: {
        id: expect.stringMatching(uuidRegexValidator),
        email: req.body.email,
      }
    })

    req = createRequest({
      body: {
        email: 'user@localhost',
        password: 'password',
      },
    })

    res = createResponse()

    await authController.login(req, res)

    expect(res._getData()).toMatchObject({
      user: {
        id: expect.stringMatching(uuidRegexValidator),
        email: req.body.email,
      },
      accessToken: expect.stringMatching(jwtRegexValidator),
      refreshToken: expect.stringMatching(jwtRegexValidator),
    })
  })
})

describe('unhappy path', () => {
  it('cannot login with an invalid password', async () => {
    await authController.ready

    await register()

    const req = createRequest({
      body: {
        email: 'user@localhost',
        password: 'wrongPassword',
      },
    })

    const res = createResponse()

    await expect(authController.login(req, res)).rejects.toThrow(Error)
  })
})

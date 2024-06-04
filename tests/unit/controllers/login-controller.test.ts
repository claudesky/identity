import { describe, expect, it, jest } from '@jest/globals'
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

describe('happy path', () => {
  it('can register and login by email', async () => {
    await authController.ready

    let req = createRequest({
      body: {
        email: 'user@localhost',
        password: 'password',
        name: 'user',
      },
    })

    let res = createResponse()

    await authController.register(req, res)

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

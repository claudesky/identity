import express from 'express'

import { authService } from './services/auth-service'
import { userRepositoryService } from './services/user-repository-service'
import { AuthController } from './controllers/auth-controller'

const authController = new AuthController(authService, userRepositoryService)

const app = express()
const port = process.env.PORT
const version = process.env.VERSION

app.get('/', (_, res) => {
  res.send({
    message: version,
  })
})

app.get('/healthcheck', (_, res) => {
  res.send({
    message: 'Healthy',
  })
})

app.post('/auth/register', (res, req) => authController.register(res, req))

app.post('/auth/login', (res, req) => authController.login(res, req))

app.post('/auth/logout', (res, req) => authController.logout(res, req))

exports.app = Promise.all([authController.ready]).then(() => {
  return app.listen(port, () => {
    console.log(`[server]: Server is running at http://localhost:${port}`)
  })
})

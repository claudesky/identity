import express from 'express'
import bodyParser from 'body-parser'

import { authService } from './services/auth-service'
import { userRepositoryService } from './services/user-repository-service'
import { AuthController } from './controllers/auth-controller'

// .env files only loaded in dev
// DEV label dropped by esbuild
DEV: {
  const dotenv = require('dotenv') as any
  dotenv.config()
}

const authController = new AuthController(authService, userRepositoryService)

const app = express()
const port = process.env.PORT || 3000
const version = process.env.VERSION

app.use(bodyParser.json())

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

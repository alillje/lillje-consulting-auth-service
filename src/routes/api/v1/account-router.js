/**
 * Account routes.
 *
 * @author Andreas Lillje
 * @version 2.3.1
 */

import express from 'express'
import jwt from 'jsonwebtoken'
import createError from 'http-errors'
import { AccountController } from '../../../controllers/api/account-controller.js'

export const router = express.Router()

const controller = new AccountController()

/**
 * Authenticates requests.
 *
 * If authentication is successful, `req.user`is populated and the
 * request is authorized to continue.
 * If authentication fails, an unauthorized response will be sent.
 *
 * @param {object} req - Express request object.
 * @param {object} res - Express response object.
 * @param {Function} next - Express next middleware function.
 */
const authenticateJWT = (req, res, next) => {
  try {
    const [authenticationScheme, token] = req.headers.authorization?.split(' ')

    if (authenticationScheme !== 'Bearer') {
      throw new Error('Invalid authentication scheme.')
    }

    // Set properties to req.user from JWT payload
    const payload = jwt.verify(token, Buffer.from(process.env.ACCESS_TOKEN_PUB, 'base64').toString('ascii'))
    req.user = {
      sub: payload.sub
    }
    next()
  } catch (err) {
    const error = createError(401)
    err.message = 'Invalid access token'
    error.cause = err
    next(error)
  }
}

/**
 * Authorizes users.
 *
 * Checks if user has right/access to access the specific user.
 *
 * @param {object} req - Express request object.
 * @param {object} res - Express response object.
 * @param {Function} next - Express next middleware function.
 */
const authorizeUser = (req, res, next) => {
  try {
    if (req.user.sub !== req.params.id) {
      throw new Error('No right to access.')
    }

    next()
  } catch (err) {
    const error = createError(403)
    error.cause = err
    next(error)
  }
}

// Provide req.user to the route if :id is present in the route path.
router.param('id', (req, res, next, id) => controller.loadUser(req, res, next, id))

// Log in
router.post('/login', (req, res, next) => controller.login(req, res, next))

// Refresh token
router.post('/refresh', (req, res, next) => controller.refreshToken(req, res, next))

// Log out
router.post('/logout', (req, res, next) => controller.logout(req, res, next))

// GET user/:id
router.get('/user/:id',
  authenticateJWT, authorizeUser,
  (req, res, next) => controller.find(req, res, next)
)

// PATCH password/:id
router.patch('/password/:id',
  authenticateJWT, authorizeUser,
  (req, res, next) => controller.updatePassword(req, res, next)
)

// PATCH /:id
router.patch('/:id',
  authenticateJWT, authorizeUser,
  (req, res, next) => controller.updateCredentials(req, res, next)
)

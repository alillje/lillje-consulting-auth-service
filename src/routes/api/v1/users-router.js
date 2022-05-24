/**
 * Users routes.
 *
 * @author Andreas Lillje
 * @version 2.3.1
 */

import express from 'express'
import jwt from 'jsonwebtoken'
import createError from 'http-errors'
import { UsersController } from '../../../controllers/api/users-controller.js'

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
    req.admin = {
      sub: payload.sub,
      admin: payload.admin
    }

    next()
  } catch (err) {
    const error = createError(401)
    error.cause = err
    next(error)
  }
}

/**
 * Authorizes admin users.
 *
 * Checks if user is admin and has right/access to access users.
 *
 * @param {object} req - Express request object.
 * @param {object} res - Express response object.
 * @param {Function} next - Express next middleware function.
 */
const authorizeAdmin = (req, res, next) => {
  try {
    if (!req.admin.admin) {
      throw new Error('No right to access.')
    }

    next()
  } catch (err) {
    const error = createError(403)
    error.cause = err
    next(error)
  }
}
export const router = express.Router()

const controller = new UsersController()

// Provide req.user to the route if :id is present in the route path.
router.param('id', (req, res, next, id) => controller.loadUser(req, res, next, id))

router.get('/', authenticateJWT, authorizeAdmin, (req, res, next) => controller.getAll(req, res, next))

router.post('/register', authenticateJWT, authorizeAdmin, (req, res, next) => controller.register(req, res, next))

router.patch('/password/reset', authenticateJWT, authorizeAdmin, (req, res, next) => controller.resetPassword(req, res, next))

// GET users/:id
router.get('/:id',
  authenticateJWT, authorizeAdmin,
  (req, res, next) => controller.find(req, res, next)
)

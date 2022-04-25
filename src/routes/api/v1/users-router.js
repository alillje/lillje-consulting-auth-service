/**
 * Users routes.
 *
 * @author Andreas Lillje
 * @version 1.0.0
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
 * Authorizes resources.
 *
 * Checks if user has right/access to a specific resource.
 *
 * @param {object} req - Express request object.
 * @param {object} res - Express response object.
 * @param {Function} next - Express next middleware function.
 */
const authorizeUser = (req, res, next) => {
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

// Provide req.image to the route if :id is present in the route path.
router.param('id', (req, res, next, id) => controller.loadUser(req, res, next, id))

// GET users/:id
router.get('/:id',
  authenticateJWT, authorizeUser,
  (req, res, next) => controller.find(req, res, next)
)

// Get user
router.get('/', authenticateJWT, authorizeUser, (req, res, next) => controller.getAll(req, res, next))

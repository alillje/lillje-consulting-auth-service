/**
 * Module for the AccountController.
 *
 * @author Andreas Lillje
 * @version 1.0.0
 */

// import createError from 'http-errors'
import jwt from 'jsonwebtoken'
import createError from 'http-errors'
import { User } from '../../models/user.js'

/**
 * Encapsulates a controller.
 */
export class AccountController {
  /**
   * Authenticates a user.
   *
   * @param {object} req - Express request object.
   * @param {object} res - Express response object.
   * @param {Function} next - Express next middleware function.
   */
  async login (req, res, next) {
    try {
      // Make username case insensitive when login
      const user = await User.authenticate(req.body.username.toLowerCase(), req.body.password)
      // Set user-id to sub (subject) in JWT payload
      const payload = {
        sub: user.id,
        username: user.username,
        email: user.email
      }
      // Create the access token with the shorter lifespan.
      const accessToken = jwt.sign(payload, Buffer.from(process.env.ACCESS_TOKEN_SECRET, 'base64').toString('ascii'), {
        algorithm: 'RS256',
        expiresIn: process.env.ACCESS_TOKEN_LIFE
      })

      res
        .status(200)
        .json({
          access_token: accessToken
        })
    } catch (err) {
      // Authentication failed.
      const error = createError(401)
      error.cause = err
      next(error)
    }
  }

  /**
   * Registers a user.
   *
   * @param {object} req - Express request object.
   * @param {object} res - Express response object.
   * @param {Function} next - Express next middleware function.
   */
  async register (req, res, next) {
    try {
      // Check all required fields exist before making request to DB.
      if (!req.body.username || !req.body.password || !req.body.email) {
        const error = new Error('Validation error')
        error.name = 'ValidationError'
        throw error
      }
      // Make username credentials case insensitive
      const user = new User({
        username: req.body.username.toLowerCase(),
        password: req.body.password,
        email: req.body.email
      })

      await user.save()

      res
        .status(201)
        .json({ id: user.id })
    } catch (err) {
      console.log(err)
      let error = err

      if (error.code === 11000) {
        // Duplicated keys.
        error = createError(409)
        error.cause = err
      } else if (error.name === 'ValidationError') {
        // Validation error(s).
        error = createError(400)
        error.cause = err
      }

      next(error)
    }
  }
}

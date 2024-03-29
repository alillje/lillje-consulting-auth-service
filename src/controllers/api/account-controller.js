/**
 * Module for the AccountController.
 *
 * @author Andreas Lillje
 * @version 2.3.1
 */

// import createError from 'http-errors'
import jwt from 'jsonwebtoken'
import createError from 'http-errors'
import validator from 'validator'
import { User } from '../../models/user.js'
import { RefreshToken } from '../../models/refresh-token.js'
import { add } from 'date-fns'

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
      const user = await User.authenticate(
        req.body.email.toLowerCase(),
        req.body.password
      )
      // Set user-id to sub (subject) in JWT payload
      const payload = {
        sub: user.id,
        company: user.company,
        admin: user.admin
      }
      // Create the access token with the shorter lifespan.
      const accessToken = jwt.sign(
        payload,
        Buffer.from(process.env.ACCESS_TOKEN_SECRET, 'base64').toString(
          'ascii'
        ),
        {
          algorithm: 'RS256',
          expiresIn: process.env.ACCESS_TOKEN_LIFE
        }
      )

      // Create the refresh token with the longer lifespan.
      const refreshToken = jwt.sign(
        payload,
        process.env.REFRESH_TOKEN_SECRET,
        {
          algorithm: 'HS256',
          expiresIn: process.env.REFRESH_TOKEN_LIFE
        }
      )

      // Check if user has exisitng refresh token in db
      const userRefreshTokenInDb = await RefreshToken.findOne({
        user: user.id
      })
      // Set expiry date for token
      if (!userRefreshTokenInDb) {
        const newRefreshToken = new RefreshToken({
          token: refreshToken,
          user: user.id,
          expire_at: add(Date.now(), { days: 1 })
        })
        await newRefreshToken.save()
        // If refresh token exist in database, set new token and save old one in usedTokens
      } else {
        await RefreshToken.findOneAndUpdate({
          user: user.id,
          token: refreshToken
        })
        await RefreshToken.findByIdAndUpdate({ _id: userRefreshTokenInDb._id.toString() }, { $push: { usedTokens: userRefreshTokenInDb.token.toString() } })
      }

      res.status(200).json({
        access_token: accessToken,
        refresh_token: refreshToken
      })
    } catch (err) {
      // Authentication failed.
      const error = createError(401)
      error.cause = err
      next(error)
    }
  }

  /**
   * Refresh an access token.
   *
   * @param {object} req - Express request object.
   * @param {object} res - Express response object.
   * @param {Function} next - Express next middleware function.
   */
  async refreshToken (req, res, next) {
    if (!req.body.refreshToken) {
      const error = createError(400)
      next(error)
      return
    }
    try {
      const requestToken = req.body?.refreshToken
      const refreshToken = await RefreshToken.findOne({ token: requestToken })

      // Check if refresh token has been used previously
      const tokenUser = jwt.decode(requestToken).sub
      const userRefreshToken = await RefreshToken.findOne({ user: tokenUser })

      // Clear all used refresh tokens and current token if misuse
      if (userRefreshToken?.usedTokens) {
        userRefreshToken.usedTokens.map(token => {
          if (token === requestToken) {
            userRefreshToken.delete()
          }
          return undefined
        })
      }

      if (!refreshToken) {
        const error = createError(401)
        error.message = 'Invalid token'
        next(error)
        return
      } else {
        jwt.verify(requestToken, process.env.REFRESH_TOKEN_SECRET)
        const tokenDecoded = jwt.decode(requestToken)
        const payload = {
          sub: tokenDecoded.sub,
          company: tokenDecoded.company,
          admin: tokenDecoded.admin
        }

        // Create the access token with the shorter lifespan.
        const newAccessToken = jwt.sign(
          payload,
          Buffer.from(process.env.ACCESS_TOKEN_SECRET, 'base64').toString(
            'ascii'
          ),
          {
            algorithm: 'RS256',
            expiresIn: process.env.ACCESS_TOKEN_LIFE
          }
        )

        const newRefreshToken = jwt.sign(
          payload,
          process.env.REFRESH_TOKEN_SECRET,
          {
            algorithm: 'HS256',
            expiresIn: process.env.REFRESH_TOKEN_LIFE
          }
        )
        // Set new refresh token and add used token to used tokens for future validation
        await RefreshToken.findOneAndUpdate({ token: newRefreshToken })
        await RefreshToken.findByIdAndUpdate({ _id: refreshToken._id.toString() }, { $push: { usedTokens: requestToken.toString() } })

        res.status(200).json({
          access_token: newAccessToken,
          refresh_token: newRefreshToken
        })
      }
    } catch (err) {
      if (err.name === 'TokenExpiredError') {
        const error = createError(401)
        error.message = 'Invalid refresh token'
        next(error)
      } else {
        next(err)
      }
    }
  }

  /**
   * Logs user out by revoking refresh token.
   *
   * @param {object} req - Express request object.
   * @param {object} res - Express response object..
   * @param {Function} next - Express next middleware function.
   */
  async logout (req, res, next) {
    try {
      if (!req.body.refreshToken) {
        const error = createError(400)
        next(error)
        return
      }
      await RefreshToken.findOneAndDelete({ token: req.body.refreshToken })

      res
        .status(204)
        .end()
    } catch (err) {
      const error = createError(400)
      error.cause = err
      next(error)
    }
  }

  /**
   * Provide req.user to the route if :id is present.
   *
   * @param {object} req - Express request object.
   * @param {object} res - Express response object.
   * @param {Function} next - Express next middleware function.
   * @param {string} id - The value of the id for the user to load.
   */
  async loadUser (req, res, next, id) {
    try {
      // Get the user.
      const user = await User.findById(id)

      // If no image found send 404, set error message.
      if (!user) {
        const error = createError(404)
        next(error)
        return
      }

      // Provide the customer to the request object.
      req.customer = user

      next()
    } catch (err) {
      let error = err
      // If id is incorrect, does not match mongoose format (CastError), send 404
      if (error.name === 'CastError') {
        error = createError(404)
        next(error)
      } else {
        next(error)
      }
    }
  }

  /**
   * Sends a JSON response containing a user.
   *
   * @param {object} req - Express request object.
   * @param {object} res - Express response object.
   * @param {Function} next - Express next middleware function.
   */
  async find (req, res, next) {
    res.json(req.customer)
  }

  /**
   * Updates a specific user partially.
   *
   * @param {object} req - Express request object.
   * @param {object} res - Express response object.
   * @param {Function} next - Express next middleware function.
   */
  async updateCredentials (req, res, next) {
    try {
      if (!req.body.email) {
        const error = createError(400)
        next(error)
      }
      // Sanitize before saving to db
      const newEmail = validator.escape(req.body.email)
      await User.findByIdAndUpdate(req.user.sub, { email: newEmail })
      res
        .status(204)
        .end()
    } catch (err) {
      console.log(err)
      const error = createError(400)
      next(error)
    }
  }

  /**
   * Updates the password of a specific user.
   *
   * @param {object} req - Express request object.
   * @param {object} res - Express response object.
   * @param {Function} next - Express next middleware function.
   */
  async updatePassword (req, res, next) {
    try {
      if (!req.body.email || !req.body.password || !req.body.newPassword || !req.body.newPasswordConfirm) {
        const error = createError(400)
        next(error)
      } else if (req.body.newPassword !== req.body.newPasswordConfirm) {
        const error = createError(400)
        next(error)
      }

      const user = await User.authenticate(
        req.body.email.toLowerCase(),
        req.body.password
      )

      user.password = req.body.newPassword
      user.save()

      res
        .status(204)
        .end()
    } catch (err) {
      console.log(err)
      let error = err
      error = createError(400)
      next(error)
    }
  }
}

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
import { RefreshToken } from '../../models/refresh-token.js'

/**
 * Encapsulates a controller.
 */
export class AccountController {
  /**
   * Authenticates a user..
   *
   * @param {object} req - Express request object.
   * @param {object} res - Express response object.
   * @param {Function} next - Express next middleware function.
   */
  async login (req, res, next) {
    try {
      // Make username case insensitive when login
      const user = await User.authenticate(
        req.body.username.toLowerCase(),
        req.body.password
      )
      // Set user-id to sub (subject) in JWT payload
      const payload = {
        sub: user.id,
        username: user.username,
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
      if (!userRefreshTokenInDb) {
        const newRefreshToken = new RefreshToken({
          token: refreshToken,
          user: user.id
        })
        newRefreshToken.save()
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
        email: req.body.email,
        admin: req.body.admin
      })

      await user.save()

      res.status(201).json({ id: user.id })
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

  /**
   * Refresh an access token.
   *
   * @param {object} req - Express request object.
   * @param {object} res - Express response object.
   * @param {Function} next - Express next middleware function.
   */
  async refreshToken (req, res, next) {
    if (!req.body.refreshToken) {
      const error = createError(403)
      next(error)
      return
    }
    try {
      const requestToken = req.body?.refreshToken
      if (!requestToken) {
        const error = createError(404)
        next(error)
        return
      }
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
        next(error)
        return
      } else {
        jwt.verify(requestToken, process.env.REFRESH_TOKEN_SECRET)
        const tokenDecoded = jwt.decode(requestToken)
        const payload = {
          sub: tokenDecoded.sub,
          username: requestToken.username,
          admin: requestToken.admin
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
      console.log(err)
      next(err)
    }
  }

  /**
   * Logs user out by revoking refresh token.
   *
   * @param {object} req - Express request object.
   * @param {object} res - Express response object.
   * @param {Function} next - Express next middleware function.
   */
  async logout (req, res, next) {
    try {
      if (!req.body.refreshToken) {
        console.log('No token provided')
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
}

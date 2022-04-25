/**
 * Module for the UsersController.
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
export class UsersController {
  /**
   * Gets all users
   *
   * @param {object} req - Express request object.
   * @param {object} res - Express response object.
   * @param {Function} next - Express next middleware function.
   */
  async getAll (req, res, next) {
    try {
      // Fine images only for authenticated user and respond
      const users = await User.find()
      res.json(users)
    } catch (error) {
      console.error(error)
      next(error)
    }
  }
}

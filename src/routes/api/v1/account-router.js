/**
 * Account routes.
 *
 * @author Andreas Lillje
 * @version 1.0.0
 */

import express from 'express'
import { AccountController } from '../../../controllers/api/account-controller.js'

export const router = express.Router()

const controller = new AccountController()

// Log in
router.post('/login', (req, res, next) => controller.login(req, res, next))

// Register
router.post('/register', (req, res, next) => controller.register(req, res, next))

// Refresh token
router.post('/refresh', (req, res, next) => controller.refreshToken(req, res, next))

// Log out
router.post('/logout', (req, res, next) => controller.logout(req, res, next))

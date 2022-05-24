/**
 * The routes.
 *
 * @author Andreas Lillje
 * @version 2.3.1
 */

import express from 'express'
import createError from 'http-errors'
import { router as v1Router } from './api/v1/router.js'

export const router = express.Router()

// /users is a proteced route available only for admin users
router.use('/api/v1', v1Router)
router.use('/api/v1/users', v1Router)

// Catch 404 (ALWAYS keep this as the last route).
router.use('*', (req, res, next) => next(createError(404)))

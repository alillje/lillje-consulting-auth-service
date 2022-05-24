/**
 * API version 1 routes.
 *
 * @author Andreas Lillje
 * @version 2.3.1
 */

import express from 'express'
import { router as accountRouter } from './account-router.js'
import { router as usersRouter } from './users-router.js'

export const router = express.Router()

router.get('/', (req, res) => res.json({ message: 'auth API' }))
router.use('/users', usersRouter)
router.use('/', accountRouter)

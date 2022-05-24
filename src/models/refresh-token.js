/**
 * Mongoose model RefreshToken.
 *
 * @author Andreas Lillje
 * @version 2.3.1
 */

import mongoose from 'mongoose'
import { add } from 'date-fns'

// Create a schema.
const schema = new mongoose.Schema({
  token: {
    type: String
  },
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  usedTokens: {
    type: Array,
    default: []
  },
  // Set expriy date for token. Document is removed after 1 day.
  expire_at: {
    type: Date,
    default: add(Date.now(), { days: 1 }),
    expires: 60
  }

}, {
  timestamps: true,
  toJSON: {
    /**
     * Performs a transformation of the resulting object to remove sensitive information.
     *
     * @param {object} doc - The mongoose document which is being converted.
     * @param {object} ret - The plain object representation which has been converted.
     */
    transform: function (doc, ret) {
      delete ret._id
      delete ret.__v
    },
    virtuals: true // ensure virtual fields are serialized
  }
})

schema.virtual('id').get(function () {
  return this._id.toHexString()
})

schema.index({ expire_at: 1 }, { expireAfterSeconds: 5 })

// Create a model using the schema.
export const RefreshToken = mongoose.model('RefreshToken', schema)

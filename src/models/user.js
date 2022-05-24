/**
 * Mongoose model User.
 *
 * @author Andreas Lillje
 * @version 2.3.1
 */

import bcrypt from 'bcrypt'
import mongoose from 'mongoose'
import validator from 'validator'

const { isEmail } = validator

// Create a schema.
const schema = new mongoose.Schema({
  company: {
    type: String,
    required: [true, 'Company is required.'],
    unique: true
  },
  // Add this to make sorting case insensitive
  companyNormalized: {
    type: String
  },
  password: {
    type: String,
    minLength: [10, 'The password must be of minimum length 10 characters.'],
    maxLength: [256, 'The password must be of maximum length 256 characters.'],
    writeOnly: true,
    required: [true, 'Password is required.']
  },
  orgNo: {
    type: String,
    unique: true,
    required: [true, 'Organization number is required.'],
    match: [/(\d{6}[-]\d{4})/, 'Please provide a valid organization number. ']

  },
  email: {
    type: String,
    required: [true, 'Email address is required.'],
    unique: true,
    lowercase: true,
    trim: true,
    validate: [isEmail, 'Please provide a valid email address.']
  },
  admin: {
    type: Boolean,
    default: false
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
      delete ret.password
    },
    virtuals: true // ensure virtual fields are serialized
  }
})

schema.virtual('id').get(function () {
  return this._id.toHexString()
})

// Salts and hashes password before save.
schema.pre('save', async function () {
  this.password = await bcrypt.hash(this.password, 10)
})

/**
 * Authenticates a user.
 *
 * @param {string} email - The email to authenticate.
 * @param {string} password - The password to authenticate.
 * @returns {Promise<User>} ...
 */
schema.statics.authenticate = async function (email, password) {
  const user = await this.findOne({ email })
  // If no user found or password is wrong, throw an error.
  if (!(await bcrypt.compare(password, user?.password))) {
    throw new Error('Invalid credentials.')
  }

  // User found and password correct, return the user.
  return user
}

// Create a model using the schema.
export const User = mongoose.model('User', schema)

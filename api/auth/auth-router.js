// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!
const router = require('express').Router()
const USER = require('../users/users-model')
const bcrypt = require('bcryptjs')
const {
     checkPasswordLength,
     checkUsernameExists,
     checkUsernameFree,
     restricted
} = require('./auth-middleware')

/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */
router.post('/register', checkUsernameFree, checkPasswordLength, (request, response, next) => {
     const { username, password } = request.body
     const hashedPassword = bcrypt.hashSync(password, 8)
     USER.add({ username, password: hashedPassword })
          .then(saved => {
               response.status(201).json(saved)
          })
          .catch(next)
})

/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */
router.post('/login', checkUsernameExists, checkPasswordLength, (request, response, next) => {
     const { password } = request.body
     if (bcrypt.compareSync(password, request.user.password)) {
          request.session.user = request.user
          response.json({ message: `Welcome ${request.user.username}` })
     }
     else {
          next({ status: 401, message: "Invalid credentials" })
     }
})

/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */
router.get('/logout', (request, response, next) => {
     if (request.session.user) {
          request.session.destroy(error => {
               if (error) {
                    next(error)
               }
               else {
                    response.json({ message: "logged out" })
               }
          })
     }
     else {
          response.json({ message: "no session" })
     }
})

// Don't forget to add the router to the `exports` object so it can be required in other modules
module.exports = router
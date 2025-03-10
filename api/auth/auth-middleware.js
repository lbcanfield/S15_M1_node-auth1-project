const USER = require('../users/users-model')
/*
  If the user does not have a session saved in the server

  status 401
  {
    "message": "You shall not pass!"
  }
*/
function restricted(request, response, next) {
     if (request.session.user) {
          next()
     }
     else {
          next({ message: "You shall not pass!", status: 401 })
     }
}

/*
  If the username in req.body already exists in the database

  status 422
  {
    "message": "Username taken"
  }
*/
async function checkUsernameFree(request, response, next) {
     try {
          const users = await USER.findBy({ username: request.body.username })
          if (!users.length) {
               next()
          }
          else {
               next({ message: "Username taken", status: 422 })
          }
     }
     catch (error) {
          next(error)
     }
}

/*
  If the username in req.body does NOT exist in the database

  status 401
  {
    "message": "Invalid credentials"
  }
*/
async function checkUsernameExists(request, response, next) {
     try {
          const users = await USER.findBy({ username: request.body.username })
          if (users.length) {
               request.user = users[0]
               next()
          }
          else {
               next({ message: "Invalid credentials", status: 401 })
          }
     }
     catch (error) {
          next(error)
     }
}

/*
  If password is missing from req.body, or if it's 3 chars or shorter

  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
*/
function checkPasswordLength(request, response, next) {
     if (!request.body.password || request.body.password.length < 3) {
          next({ message: "Password must be longer than 3 chars", status: 422 })
     }
     else {
          next()
     }
}

// Don't forget to add these to the `exports` object so they can be required in other modules
module.exports = {
     checkPasswordLength,
     checkUsernameExists,
     checkUsernameFree,
     restricted
}
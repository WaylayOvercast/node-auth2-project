const { JWT_SECRET } = require("../secrets"); // use this secret!
const jwt = require('jsonwebtoken')


function createToken(user){
 
  const payload = {
    subject: user.user_id,
    username: user.username,
    role: user.role_name,

  }
  const options = {
    expiresIn: '1d'
  }
  const result = jwt.sign(payload, JWT_SECRET , options)
  return result
}



const restricted = (req, res, next) => {
  /*
    If the user does not provide a token in the Authorization header:
    status 401
    {
      "message": "Token required"
    }

    If the provided token does not verify:
    status 401
    {
      "message": "Token invalid"
    }

    Put the decoded token in the req object, to make life easier for middlewares downstream!
  */
    const token = req.header.authorization
    if(!token){
      return next(res.status(401).json({message:'token required'}))
    }
    jwt.verify(token, JWT_SECRET, (err, decoded)=> {
      if(err){
        return next(res.status(404).json({message:'token invalid'}))
      }
      req.decoded = decoded
      next()
    })
}

const only = role_name => (req, res, next) => {
  /*
    If the user does not provide a token in the Authorization header with a role_name
    inside its payload matching the role_name passed to this function as its argument:
    status 403
    {
      "message": "This is not for you"
    }

    Pull the decoded token from the req object, to avoid verifying it again!
  */
}


const checkUsernameExists = (req, res, next) => {
  /*
    If the username in req.body does NOT exist in the database
    status 401
    {
      "message": "Invalid credentials"
    }
  */
}


const validateRoleName = (req, res, next) => {
  /*
    If the role_name in the body is valid, set req.role_name to be the trimmed string and proceed.

    If role_name is missing from req.body, or if after trimming it is just an empty string,
    set req.role_name to be 'student' and allow the request to proceed.

    If role_name is 'admin' after trimming the string:
    status 422
    {
      "message": "Role name can not be admin"
    }

    If role_name is over 32 characters after trimming the string:
    status 422
    {
      "message": "Role name can not be longer than 32 chars"
    }
  */ 

    let validate = req.body
    
  

  if(validate.role_name){

    let trim = {...validate, role_name:validate.role_name.trim()}

    if(trim.role_name === ''){
      trim = {...validate, role_name:'student'}
      req.fixRole = trim
      next()
    }else if(trim.role_name === 'admin'){
      next(res.status(422).json({message:"Role name can not be admin"}))

    }else if(trim.role_name.length >= 32){
      next(res.status(422).json({message:"Role name can not be longer than 32 chars"}))

    }else{
      req.fixRole = trim
      next()
    }
  }else{
    req.fixRole = {...validate, role_name:'student'}
    next()
  }
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
  createToken
}

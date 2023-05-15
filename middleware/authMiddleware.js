import jwt from 'jsonwebtoken'
import UserModel from '../models/User.js'

const checkAuthentication = async (req, res, next) => {
  let jwtToken;
  const { authorization } = req.headers;
  if (authorization && authorization.startsWith("Bearer")) {
    try {
      jwtToken = authorization.split(' ')[1];
      // Verify Token
      const { userId } = jwt.verify(jwtToken, process.env.JWT_SECRET_KEY);
      // GET USER FROM ID
      req.user = await UserModel.findById(userId).select('-password');
    
      next();
    } catch (error) {
      res.status(401).send({ status: 'failed', error_msg: 'Unauthorized User' });
    }
  }
  if (!jwtToken) {
    res.status(401).send({ status: 'failed', error_msg: 'Unauthorized user no token' });
  }
};

export default checkAuthentication;

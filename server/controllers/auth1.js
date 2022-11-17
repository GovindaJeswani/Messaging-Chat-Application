const bcrypt = require('bcrypt')
const crypto = require('crypto') 
const {connect} = require('getstream')
const StreamChat = require('stream-chat').StreamChat;


//! for Mongodb
const jwt = require('jsonwebtoken')
const User = require('../model/userModel');
const catchAsync = require('../utils/catchAsync');
const AppError = require('../utils/appError');


const appError = require('../utils/appError')
require('dotenv').config()

const api_key = process.env.Stream_API_Key;
const api_Secret= process.env.Stream_API_SECRET; 
const api_id = process.env.Stream_API_ID;

// sign up & login logic
const signup = async (req, res) => {
  try {
    const { fullName, username, password, phoneNumber } = req.body;
    const userId = crypto.randomBytes(16).toString("hex");
    const serverClient = connect(api_key, api_Secret, api_id);
    const hashedPassword = await bcrypt.hash(password, 10);
    const token = serverClient.createUserToken(userId);
    res.status(200).json({
      token,
      fullName,
      username,
      userId,
      hashedPassword,
      phoneNumber,
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: error });
  }
};

const login = async (req, res) => {
  try {
    const { username, password } = req.body;
    const serverClient = connect(api_key, api_Secret, api_id);
    const client = StreamChat.getInstance(api_key, api_Secret);
    const { users } = await client.queryUsers({ name: username });
    if (!users.length)
      return res.status(400).json({ message: "User not found!" });
    const success = await bcrypt.compare(password, users[0].hashedPassword);
    const token = serverClient.createUserToken(users[0].id);

    if (success) {  
      res.status(200).json({
        token,
        fullName: users[0].fullName,
        username,
        userId: users[0].id,
      });
    } else {
      res.status(500).json({
        message: "Incorrect Password!",
      });
    }
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: error });
  }
};


//! for mongoDB

const signToken = id => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN
  });
};


const createSendToken = (user, statusCode, res,req) => {
  const token = signToken(user._id);
  const cookieOptions = {
    expires: new Date(
      Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
      ),
      httpOnly: true,
      // secure: req.secure || req.headers["x-forwarded-proto"] === "https",
    };
    // if (process.env.NODE_ENV === 'production') cookieOptions.secure = true;
    
    res.cookie('jwt', token, cookieOptions);
    
    // Remove password from output
    user.password = undefined;
    
    res.status(statusCode).json({
      status: 'success',
      token,
      data: {
        user
      }
    });
  };
  
  
//  create new user

const createUser = catchAsync(async (req, res, next) => {
  try{

    const newUser = await User.create({
      fullName: req.body.fullName,
      username: req.body.username,
      phoneNumber:req.body.phoneNumber,
      password: req.body.password,
      // passwordConfirm: req.body.passwordConfirm
    });
    createSendToken(newUser, 201, res);
  } catch (err){
    console.log(err)
    res.status(500).json({message:err}); 
  }
})


const loginUser = catchAsync(async (req, res, next) => {
  try{

    const { username, password } = req.body;    
    
    // 1) Check if email and password exist
    if (!username || !password) {
      return next(new AppError('Please provide username and password!', 400));
  }
  // 2) Check if user exists && password is correct
  const user = await User.findOne({ username }).select('+password');
  
  if (!user || !(await user.correctPassword(password, user.password))) {
    return next(new AppError('Incorrect email or password', 401));
  } 
  // 3) If everything ok, send token to client
  createSendToken(user, 200, res);
}catch(err){
  console.log(err);
  res.status(500).json({message:err})
}
});


module.exports = { signup, login, createUser, loginUser};
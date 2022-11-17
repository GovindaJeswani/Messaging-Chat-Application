const express = require('express')


const { createUser,loginUser} = require("../controllers/auth1.js");
const { signup, login} = require("../controllers/auth.js");
// const authController = require('../controllers/auth')

const router = express.Router()

router.post('/signup', signup);
router.post('/login', login);

// router.post("/signup", signup);
// router.post("/login", login);

//  FOR MONGODB SERVER..

// router.post('/signupUser',createUser);
// router.post('/loginUser',loginUser);

module.exports = router




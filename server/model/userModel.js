const mongoose = require("mongoose");
const validator = require("validator");
const bcrypt = require("bcrypt");

const userSchema = new mongoose.Schema({
  fullName: { type: String, 
    required: [true, "Please tell us your name"] 
},
  username: {
    type: String,
    required: [true, "Please provide your email"],
    unique: true,
    lowercase: true,
    validate: [validator.isEmail, "Please provide a valid email"],
  },
  phoneNumber: {
    type: Number,
    required: [true, "please tell us your phone number"],
  }, 
  photo: {
    type: String,
    default: "default.jpg",
  },
  password: {
    type: String,
    required: [true, "Please provide a password"],
    minlength: 8,
    select: false,
  },
  passwordConfirm: {
    type: String,
    // required: [true, "Please confirm your password"],
    // validate: {
      // This only works on CREATE and SAVE!!!
      // validator: function (el) {
        // return el === this.password;
      // },
      // message: "Passwords are not the same!",
    },
  },
);

//  delete the passwordConfirm field from database before saved!
userSchema.pre("save", async function (next) {
  // Only run this function if password was actually modified or created otherwise return
  if (!this.isModified("password")) return next();

  // Hash the password with cost of 12
  this.password = await bcrypt.hash(this.password, 
    );

  // Delete passwordConfirm field
  this.passwordConfirm = undefined;
  next();
});

//    compare the password  with bycrypted password
userSchema.methods.correctPassword = async function (
  candidatePassword,
  userPassword
) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

const User = mongoose.model("User", userSchema);

module.exports = User;

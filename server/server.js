const express = require('express')
const cors = require('cors')
const dotenv = require('dotenv')
const mongoose = require('mongoose')

//* Required local files

const authRoutes = require("./routes/auth.js")

dotenv.config({ path: './config.env' });

const app = express()
const PORT = process.env.PORT || 5000;
const host = '127.0.0.1'

require('dotenv').config();


const accountSid = process.env.TWILIO_ACCOUNT_SID;
const authToken = process.env.TWILIO_AUTH_TOKEN;
const messagingServiceSid = process.env.TWILIO_MESSAGING_SERVICE_SID;
const twilioClient = require('twilio')(accountSid, authToken);

//! connecting to database
//   GETTING VALUE FROM DOTENV FILE
const DB = process.env.DATABASE.replace(
    '<password>',
    process.env.DATABASE_PASSWORD
  );

//    connecting with DATABASE

  mongoose.connect(DB,{
    useNewUrlParser: true,
    useUnifiedTopology: true,
    // useCreateIndex: true,
    // useFindAndModify: false
  }).then(()=>
      console.log('DB CONNECTED SUCCESSFULLY!')
  ).catch(err=>{
      if(err){
          console.log('There was some error',err.message);
      }
  })
// ///////////////////////////////////



//! Middlewares

app.use(cors())
app.use(express.json())
app.use(express.urlencoded())


//*  Routes 

app.get('/',(req,res)=>{
    res.send('get request successfully')
})
app.post('/', (req, res) => {
  const { message, user: sender, type, members } = req.body;

  if(type === 'message.new') {
      members
          .filter((member) => member.user_id !== sender.id)
          .forEach(({ user }) => {
              if(!user.online) {
                  twilioClient.messages.create({
                      body: `You have a new message from ${message.user.fullName} - ${message.text}`,
                      messagingServiceSid: messagingServiceSid,
                      to: user.phoneNumber
                  })
                      .then(() => console.log('Message sent!'))
                      .catch((err) => console.log(err));
              }
          })

          return res.status(200).send('Message sent!');
  }

  return res.status(200).send('Not a new message request');
});


app.use('/auth',authRoutes)

//*  Starting server

app.listen(PORT,host,()=>console.log(`Server is running at : http://${host}:${PORT}`))
 
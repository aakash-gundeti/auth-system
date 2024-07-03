import dotenv from 'dotenv';
import express from 'express';
import session from 'express-session';
import flash from 'connect-flash';
import bodyParser from 'body-parser';
import passport from 'passport';

import { passportConfig } from './config/passport.js';
import { connectToDatabase } from './config/db.js';
import router from './routes/index.js';
import userRouter from './routes/users.js';
import authRouter from './routes/auth.js';

//load config
dotenv.config({ path: './.env' });

const app = express();
const PORT = process.env.PORT || 3000;

app.use(session({ secret: process.env.SESSION_SECRET }));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Passport Middleware
app.use(passport.initialize());
app.use(passport.session());

// Passport Config
passportConfig(passport);

//connect flash
app.use(flash());

//Global vars
app.use((req, res, next) => {
  res.locals.success_msg = req.flash('success_msg');
  res.locals.error_msg = req.flash('error_msg');
  res.locals.error = req.flash('error');
  next();
})
// EJS
app.set('view engine', 'ejs');
app.set("views",'./views');

// Static Folder
app.use(express.static('public'));

app.use("/",router);
app.use("/users",userRouter);
app.use("/auth",authRouter);


app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  connectToDatabase();
})

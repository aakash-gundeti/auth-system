import express from 'express';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import nodemailer from 'nodemailer';

import { User } from '../models/User.js';
import {isLogin, isLogout } from '../middlewares/auth.js';

const userRouter = express.Router();

//register page
userRouter.get('/signup', isLogout, (req, res) => {
  res.render('signup',{ errors:null });
})

//login page
userRouter.get('/signin', isLogout, (req, res) => {
  res.render('signin');
})

userRouter.post("/signup", (req, res) => {
  const { email, password, confirm_password } = req.body;
  let errors = [];

  if(password !== confirm_password){
    errors.push({ msg: "Password do not match" });
  }

  if(errors.length > 0){
    res.render('signup',{
      errors,
      email,
      password,
      confirm_password
    });
  }else {
    User.findOne({ email: email }).then(user => {
      if(user){
        errors.push({ msg: "Email already registered" });
        res.render('signup',{
          errors,
          email,
          password,
          confirm_password
        }); 
      }else{
        const newUser = new User({
          email, password
        });

        bcrypt.genSalt(10, (err, salt) => {
          bcrypt.hash(newUser.password, salt, (err, hash) => {
            if(err) throw err;
            newUser.password = hash;
            newUser
              .save()
              .then(user => {
                req.flash(
                  'success_msg',
                  "You are now registered and can log in"
                );
                res.redirect("/users/signin");
              })
              .catch(err => console.log(err));
          });
        });
      }
    });
  }
});

userRouter.post("/signin", (req, res, next) => {
  // console.log('req',req.body)
  // passport.authenticate('local',{
  //   successRedirect: '/',
  //   failureRedirect: '/users/signin',
  //   failureFlash: true
  // })(req, res, next)
  const { email, password } = req.body
  User.findOne({ email: email })
    .then(user => {
      if(!user){
        req.flash(
          'error_msg',
          "This email is not registered"
        );
      }

      bcrypt.compare(password, user.password, (err, isMatch) => {
        console.log('isMatch',isMatch) 

        if(err) return err;
        if(isMatch){
          req.session.user = user;
          res.redirect("/");
        }else{
          req.flash(
            'error_msg',
            "Password incorrect"
          );
          res.redirect("/users/signin");
          // return done(null, false, { message: 'Password incorrect' });
        }
      })
    })
    .catch(err => console.log('passport', err))
});

// Logout
userRouter.get('/logout', isLogin, (req, res) => {
  req.logout(function(err){
    if(err) { return next(err) };
    req.flash('success_msg', 'You are logged out');
    res.redirect('/users/signin');
  });
});

// Reset Password Page
userRouter.get('/reset', isLogin, (req, res) => res.render('resetPassword'));

userRouter.post("/reset", async (req, res, next) => {
  const { password, confirm_password } = req.body;
  console.log('password', password);
  console.log('cpassword', confirm_password);
  if(password !== confirm_password){
    req.flash("error_msg",'Passwords dont match');
    res.redirect("/users/reset");
  }else{
    try {
      const salt = await bcrypt.genSalt(10);
      const hash = await bcrypt.hash(password, salt);
      
      await User.findByIdAndUpdate(req.session.user._id, { password: hash });
      req.flash('success_msg', 'Password updated successfully');
      res.redirect('/');
    } catch (err) {
      console.log(err);
      req.flash('error_msg', 'Failed to update password');
      res.redirect('/users/reset');
    }
  }
})

userRouter.get('/reset/:token', async (req, res) => {
  try {
    const user = await User.findOne({
      resetPasswordToken: req.params.token,
      resetPasswordExpires: { $gt: Date.now() }
    });

    if (!user) {
      req.flash('error_msg', 'Password reset token is invalid or has expired.');
      return res.redirect('/users/forgot');
    }

    res.render('resetPassword', { token: req.params.token });
  } catch (err) {
    console.error(err);
    req.flash('error_msg', 'An error occurred');
    res.redirect('/users/forgot');
  }
});

// Forgot Password Page
userRouter.get('/forgot', (req, res) => res.render('forgotPassword'));

userRouter.post("/forgot", async (req, res, next) => {
  const { email } = req.body;
  let token;

  try{
    token = await new Promise((res, rej) => {
      crypto.randomBytes(20, (err, buf) => {
        if(err) rej(err);
        res(buf.toString('hex'));
      })
    })

    const user = await User.findOneAndUpdate(
      { email },
      {
        resetPasswordToken: token,
        resetPasswordExpires: Date.now() + 3600000 // 1 hour
      },
      { new: true }
    );

    if (!user) {
      req.flash('error_msg', 'No account with that email address exists.');
      return res.redirect('/users/forgot');
    }

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: 'codingninjas2k16@gmail.com',
        pass: 'slwvvlczduktvhdj'
      }
    });

    const mailOptions = {
      to: 'jajolo9778@cutxsew.com',
      from: 'codingninjas2k16@gmail.com',
      subject: 'Password Reset',
      text: `You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n` +
        `Please click on the following link, or paste this into your browser to complete the process within one hour of receiving it:\n\n` +
        `http://${req.headers.host}/users/reset/${token}\n\n` +
        `If you did not request this, please ignore this email and your password will remain unchanged.\n`
    };

    // Send the email
    await transporter.sendMail(mailOptions);

    req.flash('success_msg', `An e-mail has been sent to ${user.email} with further instructions.`);
    res.redirect('/users/forgot');
  }catch(err){
    console.log(err);
    req.flash('error_msg', 'Failed to send reset email');
    res.redirect('/users/forgot');
  }
  
})

export default userRouter;
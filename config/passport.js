import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";

import bcrypt from 'bcryptjs';
import { User } from "../models/User.js";

export const passportConfig = (passport) => {
  passport.use(
    new LocalStrategy({ usernameField: 'email', passwordField: 'password' }, (email, password, done) => {
      User.findOne({ email: email })
        .then(user => {
          if(!user){
            return done(null, false, { message: 'This email is not registered' });
          }

          bcrypt.compare(password, user.password, (err, isMatch) => {
            console.log('isMatch',isMatch) 

            if(err) return err;
            if(isMatch){
              return done(null, user)
            }else{
              return done(null, false, { message: 'Password incorrect' });
            }
          })
        })
        .catch(err => console.log('passport', err))
    })
  )

  passport.serializeUser((user, done) => {
    done(null, user.id);
  });

  passport.deserializeUser(async (id, done) => {
    try {
      const user = await User.findById(id);
      done(null, user);
    } catch (err) {
      done(err, null);
    }
  });
}
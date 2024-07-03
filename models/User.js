import mongoose from "mongoose";

const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type:String, required: true },
  googleId: { type: String },
  resetPasswordToken: String,
  resetPasswordExpires: Date,
})

export const User = mongoose.model("User", UserSchema);
import express from 'express';
import { isLogin } from '../middlewares/auth.js';

const router = express.Router();

router.get("/", isLogin, (req, res) => {
  res.render("home",{
    user: req.user
  })
});

export default router
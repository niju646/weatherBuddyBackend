import express from "express";
import {
  signup,
  login,
  refreshToken,
  logout,
} from "../controller/authController.js";

const router = express.Router();

router.post("/signup", signup);
router.post("/login", login);
router.post("/refresh-token", refreshToken);
router.post("/logout", logout);

export default router;

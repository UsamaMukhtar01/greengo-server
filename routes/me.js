import express from "express";
import {login, signup, verifyRole, verifyUser} from "../controller/me/Authentication.js";
import {getWishlist, updateWishlist} from "../controller/me/Wishlist.js";
import { auth, signupValidator } from "../middleware/auth.js";

const router = express.Router();

router.post('/signup', signupValidator, signup);
router.post('/login', login);
router.post('/verify', auth, verifyUser);
router.post('/role', verifyRole)

router.get('/wishlist', auth, getWishlist);
router.patch('/wishlist', auth, updateWishlist);

export default router;
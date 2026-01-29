import Users from "../../model/Users.js";
import jwt from 'jsonwebtoken'
import bcrypt from 'bcrypt'
import { validationResult } from "express-validator";

export const signup = async (req, res) => {
  try {
    // Validate request
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { first_name, last_name, email, password, phone } = req.body;

    // Check if user already exists
    const existingUser = await Users.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ message: "Email already registered" });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create user
    const user = new Users({
      first_name,
      last_name,
      email,
      password: hashedPassword,
      phone,
    });

    await user.save();

    res.status(201).json({
      message: "User registered successfully",
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
};

export const login = async (req, res) => {
    const {email, password} = req.body;

    if (!email)
        return res.status(400).json({message: "Email address is not provided"})
    if (!password)
        return res.status(400).json({message: "Password address is not provided"})

    try {
        const user = await Users.findOne({email});

        if (!user)
            return res.status(404).json({message: "User was not found"})

        const isPasswordCorrect = await bcrypt.compare(password, user.password);

        if (!isPasswordCorrect)
            return res.status(400).json({message: "Wrong password"})

        const token = jwt.sign({
            id: user._id,
            email: user.email
        }, process.env.JWT_SECRET_KEY, {expiresIn: process.env.JWT_AUTH_TTL});
        return res.status(200).json({
            user: {
                _id: user._id,
                email: user.email,
                first_name: user.first_name,
                phone: user.phone,
                address: user.address,
                role: user.role,
                wishlist: user.wishlist
            },
            token
        });
    } catch (e) {
        return res.status(400).json({message: e.message});
    }
}

export const verifyUser = async (req, res) => {
    const {id} = req.user;
    try {
        const user = await Users.findById(id, {password: 0})
        return res.status(200).json({...user?._doc});
    } catch (e) {
        return res.status(404).json({message: "User not found"});
    }
}

export const verifyRole = async (req, res) => {
    try {
        const {id, role} = req.body;
        const user = await Users.findById(id, {password: 0});
        if (!user)
            return res.status(404).json({message: `User ${id} was not found`});

        if (role !== user.role)
            return res.status(401).json({message: "Unauthorized user"});

        return res.status(200).json({user});
    } catch (e) {
        return res.status(400).json({message: e.message});
    }
}
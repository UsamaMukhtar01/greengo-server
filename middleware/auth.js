import jwt from 'jsonwebtoken'
import { body } from "express-validator";

// export const auth = async (req, res, next) => {
//     try {
//         const auth = req.headers.authorization;
//         if (!auth)
//             return res.status(401).json({message: "No authorization token was provided"});
//         const token = auth.split(' ')[1];
//         const decodedData = jwt.verify(token, process.env.JWT_SECRET_KEY);
//         req.body.id = decodedData?.id;
//         next();
//     } catch (e) {
//         res.status(401).json({
//             message: e.message
//         })
//     }
// }
export const auth = (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(401).json({
                message: "Authorization token missing or malformed"
            });
        }

        const token = authHeader.split(" ")[1];

        const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);

        // Attach authenticated user to request
        req.user = {
            id: decoded.id,
            email: decoded.email
        };

        next();
    } catch (err) {
        return res.status(401).json({
            message: err.message
        });
    }
};

export const signupValidator = [
  body("email")
    .isEmail()
    .withMessage("Please provide a valid email"),

  body("password")
    .isLength({ min: 6 })
    .withMessage("Password must be at least 6 characters"),

  body("first_name")
    .optional()
    .isString(),

  body("last_name")
    .optional()
    .isString(),

  body("phone")
    .optional()
    .isString(),
];
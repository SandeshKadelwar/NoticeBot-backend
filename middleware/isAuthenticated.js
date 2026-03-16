import jwt from "jsonwebtoken";
import { User } from "../models/userModel.js";

export const isAuthenticated= (req, res, next)=>{
    try {
        const authHeader = req.headers.authorization;

        if(!authHeader || !authHeader.startsWith("Bearer ")){
            return res.status(401).json({
                success: false,
                message: "Authorization token missing/invalid"
            })
        }
        const token = authHeader.split(" ")[1]; 
        jwt.verify(token, process.env.SECRET_KEY, async (err, decoded)=>{
            if(err){
                if(err.name === 'TokenExpiredError'){
                    return res.status(400).json({
                        success: false,
                        message: "Session expired. Please log in again."
                    })
                }
                return res.status(400).json({
                    success: false,
                    message: "Access denied. Invalid token."
                })
            }
            const {id} = decoded;

            const user = await User.findById(id)
            if(!user){
                return res.status(404).json({
                    success: false,
                    message: "User not found"
                })
            }
            req.userId =user._id;
            next();
        })
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: error.message 
        })
    }
}
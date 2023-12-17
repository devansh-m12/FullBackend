import { asyncHandler } from "../utils/asyncHandler";
import jwt from "jsonwebtoken";
import { ApiError } from "../utils/ApiError";
import User from "../models/user.model";

const verifyJWT = asyncHandler(async (req, _, next) => {
    try {
        const token = req.cookies?.accessToken || req.headers("Authorization")?.replace("Bearer ", "");
        if (!token) {
            throw new ApiError(401, "Unauthorized Request");
        }
        
        const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
        const user = await User.findById(decodedToken?._id).select("-password -refreshToken");
    
        if(!user) {
            throw new ApiError(401, "Unauthorized Request");
        }
    
        req.user = user;
        next();
    } catch (error) {
        throw new ApiError(401, error?.message || "Invalid Token Access");
    }

});

export { verifyJWT };
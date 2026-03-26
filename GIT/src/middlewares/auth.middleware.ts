import type { NextFunction, Request, Response } from "express"
import jwt from "jsonwebtoken"
import dotenv from "dotenv"


dotenv.config()
export const authMiddleware = (req: Request, res: Response, next: NextFunction) => {
    const token = req.header("Authorization")?.replace("Bearer ", "")

    if (!token) {return res.status(403).send({ error: "no token provided" })
    }
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET as string)
        
        req.user = Number(decoded.sub)
        next()
    } catch (err) {
       res.status(401).send( "invalid token" )
    }
}
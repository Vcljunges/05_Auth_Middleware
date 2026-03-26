import { UserService } from "./user.services.js"
import bcrypt from "bcrypt"
const userService = new UserService()
import jwt from "jsonwebtoken"

export class AuthService {
    async authenticate(jwtSecret: string, email: string, password: string) {
        const user = await userService.findByEmail(email)

        if (!user) {
            const err = new Error("Credenciais inválidos")
            err.status = 401
            throw err
        }

        const validPassword = await bcrypt.compare(password, user.password)

        if (!validPassword) {
            const err = new Error("Credenciais inválidos")
            err.status = 401
            throw err
        }

        //criar o Secret no .env
        const token = jwt.sign({ sub: user.id, email: user.email }, jwtSecret, { expiresIn: "1h", })

        return { 
            token,
            user: { id:user.id, name: user.name, email: user.email },
        }
    }
} 
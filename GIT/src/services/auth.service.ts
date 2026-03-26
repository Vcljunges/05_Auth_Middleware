import { UserService } from "./user.service.js"
import bcrypt from "bcrypt"
import jwt from "jsonwebtoken"

const userService = new UserService()

class AppError extends Error {
    public status: number;
    constructor(message: string, status: number) {
        super(message);
        this.status = status;
    }
}

export class AuthService {
    async authenticate(jwtSecret: string, email: string, password: string) {
        const user = await userService.findByEmail(email)

        if (!user) {
            throw new AppError("Credenciais inválidos", 401)
        }

        const validPassword = await bcrypt.compare(password, user.password)

        if (!validPassword) {
            throw new AppError("Credenciais inválidos", 401)
        }

        //criar o Secret no .env
        const token = jwt.sign({ sub: user.id, email: user.email }, jwtSecret, { expiresIn: "1h", })

        return { 
            token,
            user: { id:user.id, name: user.name, email: user.email },
        }
    }
} 
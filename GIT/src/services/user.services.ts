import { prisma } from "../lib/prisma.js";
import bcrypt from "bcrypt"

//npm i bcrypt
// npm i @types/bcryptjs -D

export class UserService {
    async findAll() {
        return await prisma.user.findMany({
            orderBy: { id: "asc" },
        })
    }
    
    async findById(id: number) {
        return await prisma.user.findUnique({ 
            where: { id } ,
        })
    }

    async findByEmail(email: string) {
        return await prisma.user.findUnique({ 
            where: { email } ,
        })
    }
    

    async create(data: { name: string; email: string; password: string; role: string }) {
        // const existing = await this.findByEmail(data.email)
        // if (existing) {
        //     const err = new Error("E-mail já cadastrado")
        //     throw err
        // }

        const {password, ...anothers } = data
        const passwordHash = await bcrypt.hash(data.password, 10)



        //passa os campos e a senha criptografada
        return await prisma.user.create({
            data: {
                ...anothers,
                password: passwordHash
            },
        })
    }

    async update(id: number, data: { name?: string; password: string }) {
        return await prisma.user.update({
            where: { id },
            data,
        })
    }

    async delete(id: number) {
        return await prisma.user.delete({
            where: { id },
        })
    }
}
import type { Request, Response } from "express"
import { UserService } from "../services/user.service.js"

const userService = new UserService()

export class UserController {
    async getAll(req: Request, res: Response) {
        try {
            const users = await userService.findAll()
            return res.json(users)
        } catch (err) {
            res.status(400).json({ error: (err as Error).message })
            console.error(err)
        }
    }

    async getById(req: Request, res: Response) {
        try {
            const id = Number(req.params.id)
            const user = await userService.findById(id)
            if (!user) {
                return res.status(404).json({ message: "usuario nao encontrado" })
            }
            return res.json(user)
        } catch (err) {
            // res.status(err.status).json({ error: err.message })
            console.log(err)
        }
    }

    //criar usuario
    async create(req: Request, res: Response) {
        try {
            const { name, email, password, role } = req.body

            if (!name || !email || !password) {
                return res.status(400).json({ error: "Os campos name, email e password são obrigatórios." })
            }
            // const name = req.body.name?.trim() || null
            // const email = sanitizeEmail(req.body.email)
            // const password = String(req.body.password || "")

            // const validationError = basicValidationRegister(email, password)


            // if (validationError) {
            //     return res.status(400).json({ error: validationError })
            // }

            const user = await userService.create({ name, email, password, role })

            res.status(201).json(user)
        } catch (err) {
            res.status(400).json({ error: (err as Error).message })
        }
    }


    async update(req: Request, res: Response) {
        try {
            const id = Number(req.params.id)
            const { name, password, } = req.body

            const user = await userService.update(id, { name, password, })

            return res.json(user)
        } catch (err) {
            //console.log(err)
            return res.status(500).json({ error: "Erro ao atualizar usuários" })
        }
    }

    async delete(req: Request, res: Response) {
        try {
            const id = Number(req.params.id)

            await userService.delete(id)

            return res.status(204).send()
        } catch (err) {
            console.log(err)
            return res.status(500).json({ error: "Erro ao remover usuário" })
        }
    }
}

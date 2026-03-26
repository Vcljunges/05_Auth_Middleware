import { prisma } from "../lib/prisma.js";

export class PostService {

    async findByAuthor(id: number) {
        return await prisma.post.findMany({
        where: { authorId: id },
        orderBy: { createdAt: "desc" },
        })
    }  

    async create(data: { title: string; content?: string; authorId: number }) {
        console.log(data)
        return await prisma.post.create({ data })
    }

    async delete(id: number) {
        return await prisma.post.delete({
            where: { id },
        })
    }
}
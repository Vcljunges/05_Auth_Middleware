import type { Request, Response } from "express"
import { PostService } from "../services/post.service.js"

const postService = new PostService()

export class PostController {
  async create(req: Request, res: Response) {
    const post = await postService.create({
      title: req.body.title,
      content: req.body.content,
      authorId: req.user,  
    })

    res.status(201).json(post)
  }

    async getPosts(req: Request, res: Response) {
      console.log(req.user)
      const posts = await postService.findByAuthor(Number(req.user))

      res.json(posts)
    }

    async deletePosts(req: Request, res: Response) {
        const idPost = Number(req.params.id)
        const post = await postService.findByAuthor(idPost)

        if (post.authorId === req.user) {
            await postService.delete(idPost)
            return res.status(204)
        } else {
            return res.status(404).json({ message: "Post não localizado" })
        }
    }
}

import express  from "express";

import { authMiddleware } from "../middlewares/auth.middleware.js"
import { PostController } from "../controller/post.controller.js";


const postRouter = express.Router()

const postController = new PostController()

postRouter.post("/", authMiddleware, postController.create)

postRouter.get("/", authMiddleware, postController.getPosts)

postRouter.delete("/:id", authMiddleware, postController.deletePosts)

export default postRouter




import { Router } from "express"
import { UserController } from "../controller/user.controller.js"
import { authMiddleware } from "../middlewares/auth.middleware.js"

const userRouter = Router()
const userController = new UserController()

userRouter.post("/", userController.create)

userRouter.use(authMiddleware)

userRouter.get("/", userController.getAll)
userRouter.get("/:id", userController.getById)
// userRouter.put("/:id", userController.update)
// userRouter.delete("/:id", userController.delete)


export default userRouter

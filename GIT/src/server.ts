import  express  from "express";  
import userRouter from "./routes/user.routes.js";
import authRouter from "./routes/auth.routes.js";
import postRouter from "./routes/posts.routes.js";
import { authMiddleware } from "./middlewares/auth.middleware.js";


const app = express()
const PORT = process.env.PORT || 3000

app.use(express.json())


app.get("/health", (req, res) => {
    res.json({ status: "OK" })
})

app.use('/auth', authRouter)

app.use("/users", userRouter)

app.use("/posts", postRouter)

app.use("/admin", authMiddleware, (req, res) => {
    res.json({ status: "Bem-vindo à área administrativa!" })
})

app.listen(PORT, () => {
    console.log(`API rodando em http://localhost:${PORT}`)
})
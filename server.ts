import express, { type Request, type Response } from "express"
import cors from "cors"
import authMiddleware from "./index"
import dotenv from "dotenv"
dotenv.config()

const { OIDC_JWKS_URI = "" } = process.env

const app = express()
app.use(cors())
app.use(
  authMiddleware({
    jwksUri: OIDC_JWKS_URI,
    lax: true,
  })
)

app.get("/", (req: Request, res: Response) => {
  console.log("GET /data")
  console.log(res.locals.user)
  res.send("Data")
})

app.listen(7070, () => {
  console.log("Express listening on port 7070")
})

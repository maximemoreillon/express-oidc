import express, { type Request, type Response } from "express"
import cors from "cors"
import { introspectMiddleware, userInfoMiddleware } from "./index"
import dotenv from "dotenv"
dotenv.config()

const { OIDC_ISSUER_URL, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET } = process.env

const app = express()

app.use(cors())

// init({
//   issuer_url: OIDC_ISSUER_URL,
//   client_id: OIDC_CLIENT_ID,
//   client_secret: OIDC_CLIENT_SECRET,
// })

// app.use(introspectMiddleware)
app.use(
  userInfoMiddleware({
    issuer_url: OIDC_ISSUER_URL,
    client_id: OIDC_CLIENT_ID,
    client_secret: OIDC_CLIENT_SECRET,
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

import { NextFunction, Request, Response } from "express"
import createJwksClient from "jwks-rsa"
import jwt from "jsonwebtoken"

type Options = {
  jwksUri: string
}

const extractJwt = ({ headers, query }: Request) =>
  headers.authorization?.split(" ")[1] ??
  headers.authorization ??
  (query.jwt as string) ??
  (query.token as string)

export default ({ jwksUri }: Options) => {
  if (!jwksUri) throw `jwksUri not defined`
  const jwksClient = createJwksClient({
    jwksUri,
    cache: true,
    rateLimit: true,
  })
  return async (req: Request, res: Response, next: NextFunction) => {
    const token = extractJwt(req)
    if (!token) return res.status(401).send("Missing token")

    let decoded: any

    try {
      decoded = jwt.decode(token, { complete: true })
    } catch (error) {
      console.error(error)
      return res.status(401).send(`Token decoding failed`)
    }
    const kid = decoded.header?.kid

    if (!kid) return res.status(401).send("Token kid not found")

    const key = await jwksClient.getSigningKey(kid)

    try {
      const verified = jwt.verify(token, key.getPublicKey())

      res.locals.user = verified

      next()
    } catch (error) {
      console.error(error)
      return res.status(401).send(`Token verification failed`)
    }
  }
}

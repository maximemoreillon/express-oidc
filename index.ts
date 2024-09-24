import { NextFunction, Request, Response } from "express"
import createJwksClient from "jwks-rsa"
import jwt from "jsonwebtoken"

type Options = {
  jwksUri: string
  lax?: boolean
}

const extractJwt = ({ headers, query }: Request) =>
  headers.authorization?.split(" ")[1] ??
  headers.authorization ??
  (query.jwt as string) ??
  (query.token as string)

export default ({ jwksUri, lax }: Options) => {
  if (!jwksUri) throw new Error(`jwksUri not defined`)

  const jwksClient = createJwksClient({
    jwksUri,
    cache: true,
    rateLimit: true,
  })

  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const token = extractJwt(req)
      if (!token) throw new Error("Missing token")

      const decoded = jwt.decode(token, { complete: true })
      if (!decoded) throw new Error(`Decoded token is null`)

      const kid = decoded.header?.kid
      if (!kid) throw new Error("Missing token kid")

      const key = await jwksClient.getSigningKey(kid)

      const verified = jwt.verify(token, key.getPublicKey())

      res.locals.user = verified

      next()
    } catch (error: any) {
      if (lax) return next()
      console.error(error)
      return res.status(401).send(error.toString())
    }
  }
}

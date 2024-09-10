import { type NextFunction, type Request, type Response } from "express"
import { BaseClient, Issuer } from "openid-client"

type Options = {
  issuer_url?: string
  client_id?: string
  client_secret?: string
}

let client: BaseClient
export const getClient = () => client

// https://www.npmjs.com/package/openid-client/v/2.4.3#manually-recommended
/* 
> You should provide at least the following metadata: 
  - client_id, 
  - client_secret, 
  - id_token_signed_response_alg (defaults to RS256) 
  - token_endpoint_auth_method (defaults to client_secret_basic) 
  for a basic client definition, but you may provide any IANA registered client metadata.
*/
// Note: for the userInfo method, client_secret is not needed
// This probably implies that the token is not verified
export const clientInit = async (options: Options) => {
  const { issuer_url, client_id, client_secret } = options
  if (!issuer_url) throw new Error(`Mssing issuer_url`)
  if (!client_id) throw new Error(`Mssing client_id`)
  const issuer = await Issuer.discover(issuer_url)
  client = new issuer.Client({
    client_id,
    client_secret, // Necessary for introspect
  })
}

function getToken(req: Request) {
  const { headers, query } = req
  return (query.token ?? query.jwt ?? headers.authorization?.split(" ")[1]) as
    | string
    | undefined
}

// Problem: Middleware can probably not be async
export const introspectMiddleware = (options: Options | undefined) => {
  if (options) clientInit(options)
  return async (req: Request, res: Response, next: NextFunction) => {
    const client = getClient()
    if (!client) throw new Error("Client not initialized")
    const token = getToken(req)
    if (!token || token === "undefined")
      return res.status(401).send("Missing token")

    try {
      const introspection = await client.introspect(token)
      // NOTE: Introspection works even if token is "undefined", resulting in {active: false}
      if (!introspection.active) return res.status(401).send("Not active")
      res.locals.user = introspection
      next()
    } catch (error) {
      console.error(error)
      res.status(401).send(error)
    }
  }
}

export const userInfoMiddleware = (options: Options | undefined) => {
  if (options) clientInit(options)
  return async (req: Request, res: Response, next: NextFunction) => {
    const client = getClient()
    if (!client) throw new Error("Client not initialized")
    const token = getToken(req)
    if (!token || token === "undefined")
      return res.status(401).send("Missing token")

    try {
      const userInfo = await client.userinfo(token)
      res.locals.user = userInfo
      next()
    } catch (error) {
      console.error(error)
      res.status(401).send(error)
    }
  }
}

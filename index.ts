import passport from "passport"
import { ExtractJwt, Strategy, VerifiedCallback } from "passport-jwt"
import { passportJwtSecret } from "jwks-rsa"

type Options = {
  jwksUri: string
}

export default function ({ jwksUri }: Options) {
  const verify = (payload: any, done: VerifiedCallback) => {
    done(null, payload)
  }

  const passportJwtSecretOptions = {
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 5,
    jwksUri,
  }
  const options = {
    secretOrKeyProvider: passportJwtSecret(passportJwtSecretOptions),
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  }

  const strategy = new Strategy(options, verify)
  passport.use(strategy)

  return passport.authenticate("jwt", { session: false })
}

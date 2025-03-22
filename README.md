# Express OIDC

This is an authentication middleware that validates JWT from OIDC providers using JWKS.

## Installation

```bash
npm i @moreillon/express-oidc
```

## Usage

```ts
import express, { type Request, type Response } from "express";
import authMiddleware from "@moreillon/express-oidc";

const app = express();
app.use(
  authMiddleware({
    jwksUri: "http://your-identity-provider/path-to-jwks",
  })
);

app.get("/", (req: Request, res: Response) => {
  console.log("GET /data");
  console.log(res.locals.user);
  res.send("Data");
});

app.listen(7070, () => {
  console.log("Express listening");
});
```

## Notes

- Seems to match the content of [this article](https://traveling-coderman.net/code/node-architecture/authentication/)
- [Auth0's express-oauth2-jwt-bearer library](https://github.com/auth0/node-oauth2-jwt-bearer/tree/main/packages/express-oauth2-jwt-bearer) Could be a better alternative

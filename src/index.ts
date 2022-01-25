import { decode, verify, Algorithm, JwtPayload } from 'jsonwebtoken'
import { Request, Response, NextFunction } from 'express'
import { JWK } from 'node-jose'
import jwkToPem, { JWK as JWKKey } from 'jwk-to-pem'
import axios from 'axios'

declare module 'http' {
  interface IncomingHttpHeaders {
    authorizationinfo?: string
  }
}
declare module 'express' {
  interface Request {
    user?: JwtPayload
  }
}

export interface Options {
  issuer: string
  audience: string
  algorithms: string | Algorithm[]
}

interface RawKeys {
  keys: JWK.RawKey[]
}

const tokenBlacklist = new Map<string, boolean>()

const JWKS: Record<string, RawKeys> = {}

const getPublicKey = (kid, keys: JWK.RawKey[]): JWK.RawKey | undefined => {
  return keys.find((k: JWK.RawKey) => k.kid === kid)
}

function isJwtPayload(jwt: string | JwtPayload): jwt is JwtPayload {
  return (jwt as JwtPayload).iss !== undefined
}

// It's good practice in any JWT based system to build a way to blacklist tokens
// as in some token systems expiry times can be very long.
// Blacklisting also lets us recover from token leaks or enable users to log out
// securely even if their token would otherwise still be valid if an unauthorized
// party were to retrieve their token.
const isBlacklisted = (jwt: JwtPayload) => {
  return tokenBlacklist.get(jwt.sub) === true
}

const authorize =
  (options: Options) =>
  async (
    req: Request,
    res: Response,
    next: NextFunction,
  ): Promise<Response | void> => {
    //Our library could still be used by non TS code so always good to triple check
    const { issuer, audience, algorithms } = options
    if (!issuer || !audience || !algorithms) {
      return next(
        new Error(
          'Auth middleware misconfigured. Missing one of required Options (issuer, audience, algorithms)',
        ),
      )
    }

    //Cache the json web keys
    if (JWKS?.[issuer] === undefined) {
      try {
        const jwksPayload = await axios.get<RawKeys>(
          `${issuer.replace(/\/$/, '')}/.well-known/jwks.json`,
          {
            timeout: 2000,
          },
        )

        if (jwksPayload.status > 300) {
          throw jwksPayload.statusText
        }
        JWKS[issuer] = jwksPayload.data
      } catch (e) {
        return next(
          new Error(
            `Failed to retrieve /.well-known/jwks.json from issuer: ${issuer}\n${e}`,
          ),
        )
      }
    }

    const { authorizationinfo } = req.headers
    if (!authorizationinfo) {
      return res.status(401).json({
        status: 'unauthorized',
      })
    }

    const userKey = decode(authorizationinfo, { complete: true })
    const publicKey = getPublicKey(userKey?.header?.kid, JWKS[issuer].keys)
    if (!publicKey) {
      return res.status(401).json({
        status: 'unauthorized',
      })
    }

    try {
      const pem = jwkToPem(publicKey as JWKKey)
      const verifiedToken = verify(authorizationinfo, pem, {
        // Did type checking here to conform to how the test spec intended to send
        // the algorithm setting as a string. I wanted to maintain an option to send an array
        algorithms:
          typeof algorithms === 'string'
            ? ([algorithms] as Algorithm[])
            : algorithms,
      })

      //Verify we've decoded correctly
      if (!isJwtPayload(verifiedToken)) {
        return res.status(401).json({
          status: 'unauthorized',
        })
      }

      //Check if token is valid within our systems
      if (isBlacklisted(verifiedToken)) {
        return res.status(401).json({
          status: 'unauthorized',
        })
      }

      //Token expiry
      if (userKey.payload.exp < Math.floor(Date.now() / 1000)) {
        return res.status(401).json({
          status: 'unauthorized',
        })
      }

      //Verify audience
      if (userKey.payload.aud !== audience) {
        return res.status(401).json({
          status: 'unauthorized',
        })
      }

      //Verify issuer matches our cognito user pool
      if (userKey.payload.iss !== issuer) {
        return res.status(401).json({
          status: 'unauthorized',
        })
      }

      //Verify token use
      if (['id', 'access'].includes(userKey.payload.token_use) === false) {
        return res.status(401).json({
          status: 'unauthorized',
        })
      }

      req.user = verifiedToken
      return next()
    } catch (e) {
      console.warn(e)
      return res.status(401).json({
        status: 'unauthorized',
      })
    }
  }

export default authorize

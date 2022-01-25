import nock from 'nock'
import { createRequest, createResponse } from 'node-mocks-http'
import authorise, { Options } from './index'
import TokenGenerator from './__tests__/TokenGenerator'

const tokenGenerator = new TokenGenerator()
const options: Options = {
  issuer: 'http://issuer.com',
  audience: 'audience',
  algorithms: 'RS256',
}
const failingIssuer = 'http://failingissuer.com'
const currentTime = Math.round(Date.now() / 1000)
const claims = {
  sub: 'foo',
  iss: options.issuer,
  aud: options.audience,
  exp: currentTime + 10,
  token_use: 'id',
}

beforeAll(async () => {
  await tokenGenerator.init()

  nock(options.issuer)
    .persist()
    .get('/.well-known/jwks.json')
    .reply(200, { keys: [tokenGenerator.jwk] })
})

describe('A request with a valid access token', () => {
  // Valid jwks published

  test('should add a user object containing the token claims to the request', async () => {
    const res = createResponse()
    const next = jest.fn()
    const token = await tokenGenerator.createSignedJWT(claims)
    const req = createRequest({
      headers: {
        authorizationinfo: token,
      },
    })

    await authorise(options)(req, res, next)
    expect(req).toHaveProperty('user', claims)
    expect(next).toHaveBeenCalledWith() //Should call to next with no params
  })
})

describe('A request with an invalid token', () => {
  test('should return an Unauthorized response', async () => {
    const res = createResponse()
    const next = jest.fn()
    const req = createRequest({
      headers: {
        authorizationinfo: 'invalid',
      },
    })

    await authorise(options)(req, res, next)
    expect(res.statusCode).toBe(401)
    expect(res._getJSONData()).toStrictEqual({
      status: 'unauthorized',
    })
    expect(next).not.toHaveBeenCalled()
  })

  test('should return an Unauthorized response when no token provided', async () => {
    const res = createResponse()
    const next = jest.fn()
    const req = createRequest()

    await authorise(options)(req, res, next)
    expect(res.statusCode).toBe(401)
    expect(res._getJSONData()).toStrictEqual({
      status: 'unauthorized',
    })
    expect(next).not.toHaveBeenCalled()
  })

  test('should return an Unauthorized response when token has expired', async () => {
    const res = createResponse()
    const next = jest.fn()
    const token = await tokenGenerator.createSignedJWT({
      ...claims,
      exp: currentTime - 10,
    })
    const req = createRequest({
      headers: {
        authorizationinfo: token,
      },
    })
    await authorise(options)(req, res, next)
    expect(res.statusCode).toBe(401)
    expect(res._getJSONData()).toStrictEqual({
      status: 'unauthorized',
    })
    expect(next).not.toHaveBeenCalled()
  })

  test('should return an Unauthorized response when audience is missmatched', async () => {
    const res = createResponse()
    const next = jest.fn()
    const token = await tokenGenerator.createSignedJWT({
      ...claims,
      aud: 'false',
    })
    const req = createRequest({
      headers: {
        authorizationinfo: token,
      },
    })
    await authorise(options)(req, res, next)
    expect(res.statusCode).toBe(401)
    expect(res._getJSONData()).toStrictEqual({
      status: 'unauthorized',
    })
    expect(next).not.toHaveBeenCalled()
  })

  test('should return an Unauthorized response when token_use is invalid', async () => {
    const res = createResponse()
    const next = jest.fn()
    const token = await tokenGenerator.createSignedJWT({
      ...claims,
      token_use: 'false',
    })
    const req = createRequest({
      headers: {
        authorizationinfo: token,
      },
    })
    await authorise(options)(req, res, next)
    expect(res.statusCode).toBe(401)
    expect(res._getJSONData()).toStrictEqual({
      status: 'unauthorized',
    })
    expect(next).not.toHaveBeenCalled()
  })

  test('should return an Unauthorized response when token_use is invalid', async () => {
    const res = createResponse()
    const next = jest.fn()
    const token = await tokenGenerator.createSignedJWT({
      ...claims,
      token_use: 'false',
    })
    const req = createRequest({
      headers: {
        authorizationinfo: token,
      },
    })
    await authorise(options)(req, res, next)
    expect(res.statusCode).toBe(401)
    expect(res._getJSONData()).toStrictEqual({
      status: 'unauthorized',
    })
    expect(next).not.toHaveBeenCalled()
  })
})

describe('An invalid configuration', () => {
  test('should return an error if the middleware is not configured', async () => {
    const res = createResponse()
    const next = jest.fn()
    const req = createRequest()

    await authorise({} as Options)(req, res, next)
    expect(next).toHaveBeenCalledWith(
      new Error(
        'Auth middleware misconfigured. Missing one of required Options (issuer, audience, algorithms)',
      ),
    )
  })

  test('should return an error if the middleware is misconfigured', async () => {
    const res = createResponse()
    const next = jest.fn()
    const req = createRequest()

    await authorise({
      issuer: 'issuer',
      audience: '',
      algorithms: 'algorithm',
    })(req, res, next)
    expect(next).toHaveBeenCalledWith(
      new Error(
        'Auth middleware misconfigured. Missing one of required Options (issuer, audience, algorithms)',
      ),
    )
  })

  test('should return an error if the issuer is not returning a 200 response', async () => {
    nock(failingIssuer).get('/.well-known/jwks.json').reply(500)

    const res = createResponse()
    const next = jest.fn()
    const token = await tokenGenerator.createSignedJWT(claims)
    const req = createRequest({
      headers: {
        authorizationinfo: token,
      },
    })

    await authorise({
      issuer: failingIssuer,
      audience: 'audience',
      algorithms: 'RS256',
    })(req, res, next)

    expect(next).toHaveBeenCalledWith(
      new Error(
        `Failed to retrieve /.well-known/jwks.json from issuer: ${failingIssuer}\nError: Request failed with status code 500`,
      ),
    )
  })

  test('should return an error if the issuer times out', async () => {
    nock(failingIssuer)
      .get('/.well-known/jwks.json')
      .delayConnection(5000)
      .reply(200)
    const res = createResponse()
    const next = jest.fn()
    const token = await tokenGenerator.createSignedJWT(claims)
    const req = createRequest({
      headers: {
        authorizationinfo: token,
      },
    })

    await authorise({
      issuer: failingIssuer,
      audience: 'audience',
      algorithms: 'RS256',
    })(req, res, next)

    expect(next).toHaveBeenCalledWith(
      new Error(
        `Failed to retrieve /.well-known/jwks.json from issuer: ${failingIssuer}\nError: timeout of 2000ms exceeded`,
      ),
    )
  })
})

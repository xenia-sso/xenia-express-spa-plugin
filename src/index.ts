import { Response, Router } from "express";
import { ConfigureOptions as SsoToolsOptions, IdToken, SsoTools } from "./SsoTools";
import { authMiddleware } from "./middlewares/auth";
import { asyncMiddleware } from "middleware-async";
import { refreshTokenMiddleware } from "./middlewares/refresh-token";
import jwt from "jsonwebtoken";
import { DateTime } from "luxon";
import { UNAUTHORIZED_PAYLOAD } from "./errors/Unauthorized";
import { readFileSync, promises as fsPromises } from "fs";

const router = Router();

interface AccessToken {
  userId: string;
  token: string;
  createdAt: number;
}

interface CodeTuple {
  codeChallenge: string;
  codeVerifier: string;
}

export const accessTokens: AccessToken[] = [];
const codeTuples: CodeTuple[] = [];

let _authMiddleware: any;
let _refreshTokenMiddleware: any;
export const AuthMiddleware: any = asyncMiddleware((...args: any) => _authMiddleware?.(...args));
export const RefreshTokenMiddleware: any = asyncMiddleware((...args: any) => _refreshTokenMiddleware?.(...args));

interface PluginOptions extends SsoToolsOptions {
  jwtKey: string;
  createdRoutesPrefix?: string;
  persistSessions?: boolean;
  sessionsFilePath?: string;
}

let ssoTools: SsoTools;
export default (options: PluginOptions) => {
  ssoTools = new SsoTools(options);
  _authMiddleware = authMiddleware(options.jwtKey, ssoTools);
  _refreshTokenMiddleware = refreshTokenMiddleware(options.jwtKey, ssoTools);

  if (options.persistSessions && options.sessionsFilePath) {
    try {
      const fileContent = readFileSync(options.sessionsFilePath).toString("utf-8");
      const fileAccessTokens = JSON.parse(fileContent) as AccessToken[];
      for (const token of fileAccessTokens) {
        accessTokens.push(token);
      }
    } catch {}
  }

  const updateSessionsFile = () => {
    if (options.persistSessions && options.sessionsFilePath) {
      fsPromises.writeFile(options.sessionsFilePath, JSON.stringify(accessTokens)).catch(() => {
        /* Silent fail */
      });
    }
  };

  const prefix = options.createdRoutesPrefix || "";

  router.get(
    `${prefix}/oauth2/user`,
    AuthMiddleware as any,
    asyncMiddleware(async (req, res: Response) => {
      res.json(res.locals.user);
    }) as any
  );

  router.post(`${prefix}/oauth2/code-challenge`, (req, res) => {
    const { codeChallenge, codeVerifier } = ssoTools.generateCodes();
    codeTuples.push({ codeChallenge, codeVerifier });
    res.json({ codeChallenge });
  });

  router.post(`${prefix}/oauth2/logout`, AuthMiddleware as any, (req, res) => {
    res.clearCookie("refresh_token");
    const token = res.locals.accessToken.token;
    ssoTools.revokeToken(token);
    const accessTokenIndex = accessTokens.findIndex((t) => t.token === token);
    if (accessTokenIndex !== -1) {
      accessTokens.splice(accessTokenIndex, 1);
      updateSessionsFile();
    }
    res.json({ success: true });
  });

  router.post(`${prefix}/oauth2/token`, async (req, res) => {
    const authorizationCode = req.query.authorizationCode as string;
    const codeChallenge = req.query.codeChallenge as string;
    if (!authorizationCode || !codeChallenge) {
      return res.status(401).json({ ...UNAUTHORIZED_PAYLOAD, message: "Missing authorizationCode or codeChallenge." });
    }

    const codeTupleIndex = codeTuples.findIndex((t) => t.codeChallenge === codeChallenge);
    if (codeTupleIndex === -1) {
      return res.status(401).json({ ...UNAUTHORIZED_PAYLOAD, message: "Code verifier not found." });
    }
    const codeVerifier = codeTuples.splice(codeTupleIndex, 1)[0].codeVerifier;
    const data = await ssoTools.token(codeVerifier, authorizationCode);
    if (!data) {
      return res.status(401).json({ ...UNAUTHORIZED_PAYLOAD, message: "Unable to get access token." });
    }

    const userinfo = jwt.decode(data.id_token) as IdToken;
    accessTokens.push({ userId: userinfo.sub, token: data.access_token, createdAt: Date.now() });
    updateSessionsFile();

    res.cookie(
      "refresh_token",
      jwt.sign({ userId: userinfo.sub, refresh: true }, options.jwtKey, {
        expiresIn: "90 days",
      }),
      {
        httpOnly: true,
        sameSite: true,
        expires: DateTime.now().plus({ days: 90 }).toJSDate(),
      }
    );

    res.json({
      token: jwt.sign({ userId: userinfo.sub, email: userinfo.email, refresh: false }, options.jwtKey, {
        expiresIn: "15 min",
      }),
      user: ssoTools.idTokenToUserObj(userinfo),
    });
  });

  router.post(`${prefix}/oauth2/refresh`, RefreshTokenMiddleware, (req, res) => {
    const userId = res.locals.userId;

    res.json({
      token: jwt.sign({ userId, refresh: false }, options.jwtKey, {
        expiresIn: "15 min",
      }),
    });
  });

  return router;
};

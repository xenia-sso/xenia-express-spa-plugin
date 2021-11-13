import { NextFunction, Request, Response } from "express";
import jwt, { JwtPayload } from "jsonwebtoken";
import { accessTokens } from "..";
import { UNAUTHORIZED_PAYLOAD } from "../errors/Unauthorized";
import { SsoTools } from "../SsoTools";

export const refreshTokenMiddleware = (jwtKey: string, ssoTools: SsoTools) => {
  const use = async (req: Request, res: Response, next: NextFunction) => {
    const token = req.cookies?.["refresh_token"];
    if (!token) {
      return res.status(401).send(UNAUTHORIZED_PAYLOAD);
    }

    let decoded: JwtPayload;
    try {
      decoded = jwt.verify(token, jwtKey) as JwtPayload;
    } catch {
      return res.status(401).send(UNAUTHORIZED_PAYLOAD);
    }

    if (!decoded.refresh) {
      return res.status(401).send(UNAUTHORIZED_PAYLOAD);
    }

    const userId = decoded.userId as string;
    const accessToken = accessTokens.find((t) => t.userId === userId);
    if (!accessToken) {
      return res.status(401).send({ ...UNAUTHORIZED_PAYLOAD, message: "Access token not found." });
    }

    const { active } = await ssoTools.introspect(accessToken.token);
    if (!active) {
      return res.status(401).send({ ...UNAUTHORIZED_PAYLOAD, message: "Inactive access token." });
    }

    res.locals.userId = userId;
    next();
  };

  return use;
};

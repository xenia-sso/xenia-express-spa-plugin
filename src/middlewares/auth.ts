import { NextFunction, Request, Response } from "express";
import jwt, { JwtPayload } from "jsonwebtoken";
import { accessTokens } from "..";
import { UNAUTHORIZED_PAYLOAD } from "../errors/Unauthorized";
import { SsoTools } from "../SsoTools";

export const authMiddleware = (jwtKey: string, ssoTools: SsoTools) => {
  const use = async (req: Request, res: Response, next: NextFunction) => {
    const token = req.headers.authorization;
    if (!token) {
      return res.status(401).send(UNAUTHORIZED_PAYLOAD);
    }

    let decoded: JwtPayload;
    try {
      decoded = jwt.verify(token, jwtKey) as JwtPayload;
    } catch {
      return res.status(401).json(UNAUTHORIZED_PAYLOAD);
    }

    if (decoded.refresh) {
      return res.status(401).send();
    }

    const userId = decoded.userId as string;
    const accessToken = accessTokens.find((t) => t.userId === userId);
    if (!accessToken) {
      return res.status(401).send({ ...UNAUTHORIZED_PAYLOAD, message: "Access token not found." });
    }

    const data = await ssoTools.userinfo(accessToken.token);
    if (!data) {
      return res.status(401).send({ ...UNAUTHORIZED_PAYLOAD, message: "Unable to get user info." });
    }

    res.locals.user = data;
    res.locals.accessToken = accessToken;
    next();
  };

  return use;
};

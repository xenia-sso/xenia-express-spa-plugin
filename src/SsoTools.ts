import { createHash } from "crypto";
import fetch from "cross-fetch";
import { generate } from "randomstring";
import { decode } from "jsonwebtoken";

export interface ConfigureOptions {
  baseUrl: string;
  // endpoints
  tokenEndpointPath?: string;
  introspectEndpointPath?: string;
  userinfoEndpointPath?: string;
  revokeTokenEndpointPath?: string;
  // id & secret
  clientId: string;
  clientSecret: string;
}

export interface IdToken {
  sub: string;
  email: string;
  given_name: string;
  family_name: string;
}

interface TokenResponse {
  token_type: string;
  access_token: string;
  scope: string;
  id_token: string;
}

export class SsoTools {
  private options: ConfigureOptions;

  constructor(options: ConfigureOptions) {
    this.options = options;
  }

  generateCodes = () => {
    const codeVerifier = generate({ length: 128 });
    const codeChallenge = createHash("sha256")
      .update(codeVerifier)
      .digest("base64")
      .toString()
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");

    return {
      codeVerifier,
      codeChallenge,
    };
  };

  buildUrl = (path = "", queryParams: Record<string, string> = {}) => {
    let url = `${this.options.baseUrl}${path}`;
    if (Object.keys(queryParams).length > 0) {
      url = `${url}?${Object.entries(queryParams)
        .map(([key, value]) => `${key}=${encodeURIComponent(value)}`)
        .join("&")}`;
    }
    return url;
  };

  fetchSSO = async (url: string, init?: RequestInit) => {
    const options = init || {};
    options.headers = {
      ...(options.headers || {}),
      client_id: this.options.clientId,
      client_secret: this.options.clientSecret,
    };
    try {
      const res = await fetch(url, options);
      if (!res.ok) {
        throw new Error();
      }
      return res;
    } catch (e) {
      throw e;
    }
  };

  userinfo = async (token: string) => {
    const url = this.buildUrl(this.options.userinfoEndpointPath || "/oidc/userinfo", { token });
    try {
      const res = await this.fetchSSO(url);
      return (await res.json()) as { id_token: string };
    } catch {
      return undefined;
    }
  };

  introspect = async (token: string) => {
    const url = this.buildUrl(this.options.introspectEndpointPath || "/oauth2/introspect", { token });
    try {
      const res = await this.fetchSSO(url, { method: "POST" });
      return (await res.json()) as { active: boolean };
    } catch {
      return { active: false };
    }
  };

  token = async (codeVerifier: string, authorizationCode: string) => {
    const url = this.buildUrl(this.options.tokenEndpointPath || "/oauth2/token", {
      grant_type: "authorization_code",
      code_verifier: codeVerifier,
      code: authorizationCode,
    });

    try {
      const res = await this.fetchSSO(url, { method: "POST" });
      return (await res.json()) as TokenResponse;
    } catch {
      return undefined;
    }
  };

  revokeToken = async (token: string) => {
    const url = this.buildUrl(this.options.revokeTokenEndpointPath || "/oauth2/revoke-token", { token });
    try {
      const res = await this.fetchSSO(url, { method: "POST" });
      return (await res.json()) as { success: boolean };
    } catch {
      return { success: false };
    }
  };

  idTokenStrToUserObj = (idToken: string) => {
    const userinfo = decode(idToken) as IdToken;
    return this.idTokenToUserObj(userinfo);
  };

  idTokenToUserObj = (idToken: IdToken) => {
    return {
      id: idToken.sub,
      email: idToken.email,
      firstName: idToken.given_name,
      lastName: idToken.family_name,
    };
  };
}

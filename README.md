# Xenia Express SPA Plugin

Xenia plugin for Express.

## Features

- Authorization code flow
  - Code challenge generation
  - Access token query to Xenia server
- User session handling
  - Short-lived primary token
  - Refresh token
- Auth middleware
  - Prevent unauthenticated users to access protected routes
  - Add current user info to request context
- Logout route

## Installation

```bash
npm i @xenia-sso/express-spa-plugin
```

## Configuration

1. Import Xenia global middleware

```javascript
import xenia from "@xenia-sso/express-spa-plugin";
// OR
const { default: xenia } = require("@xenia-sso/express-spa-plugin");
```

2. Mount middleware

```javascript
app.use(
  xenia({
    // Xenia server base URL
    baseUrl: "http://localhost:3000",
    // Client info
    clientId: "[MY_CLIENT_ID]",
    clientSecret: "[MY_CLIENT_SECRET]",
    // JWT key used to decode and encode user session tokens. Must be a long and random string.
    jwtKey: "[MY_JWT_KEY]",
    // OPTIONAL: Prefix added to all routes created by the plugin. Must match your existing routes prefix.
    createdRoutesPrefix: "/api",
    // OPTIONAL: By default sessions are stored in memory. In development mode, you may want to
    // keep your user logged in after server reboot.
    persistSessions: true,
    sessionsFilePath: "/path/to/file.json",
  })
);
```

3. Enable CORS if needed

```javascript
const cors = require("cors");

app.use(cors({ origin: "[FRONTEND_ORIGIN]", credentials: true }));
```

Make sure to enable `credentials` mode and to set your front-end `origin` url (`*` [will not work](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS/Errors/CORSNotSupportingCredentials)).

## Usage

Add the `AuthMiddleware` to any route you want to protect:

- Unauthenticated users in will get a unauthorized error
- Current user will be available through `res.locals.user`

```javascript
import { AuthMiddleware } from "@xenia-sso/express-spa-plugin";
// OR
const { AuthMiddleware } = require("@xenia-sso/express-spa-plugin");

app.get("/api/some-ws", AuthMiddleware, (req, res) => {
  console.log(res.locals.user);
  // Will output:
  // {
  //   sub: '[USER_ID]',
  //   email: '[USER_EMAIL]',
  //   given_name: '[USER_GIVEN_NAME]',
  //   family_name: '[USER_FAMILY_NAME]'
  // }

  // ...
});
```

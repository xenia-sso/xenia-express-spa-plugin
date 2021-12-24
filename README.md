# Xenia Express SPA Plugin

Xenia plugin for Express.

## Features

- Authorization code flow
  - Code challenge generation
  - Access token query
- User session handling
- Auth middleware
- Logout route

## Configuration

```javascript
import xenia from "xenia-express-plugin";

app.use(
  xenia({
    // Xenia server base URL
    baseUrl: "http://localhost:3000/api",
    // Client info
    clientId: "[MY_CLIENT_ID]",
    clientSecret: "[MY_CLIENT_SECRET]",
    // JWT key used to decode and encode user session tokens
    jwtKey: "[MY_JWT_KEY]",
    // Prefix used by all routes created by the plugin
    createdRoutesPrefix: "/api",
    // By default sessions are stored in memory. In development mode, you may want to keep your user logged in
    // after server reboot.
    persistSessions: true,
    sessionsFilePath: "/path/to/file.json",
  })
);
```

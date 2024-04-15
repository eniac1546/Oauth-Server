"use strict";

require('dotenv').config();
const PORT = process.env.PORT || 8000;
const app = require("./app");
const server = app.app.listen(PORT);

console.log("Running on http://localhost:" + PORT);
console.log("\nST Connector configuration configuration:")
console.log("Client ID:           " + app.EXPECTED_CLIENT_ID);
console.log("Client Secret:       " + app.EXPECTED_CLIENT_SECRET);
console.log("Authorization URI:   " + app.AUTH_REQUEST_PATH);
console.log("Refresh Token URL:   " + app.ACCESS_TOKEN_REQUEST_PATH);
console.log("Access Token Prefix: " + app.ACCESS_TOKEN_PREFIX)

process.on("SIGTERM", function() {
  server.close(() => {
    process.exit(0);
  });
});

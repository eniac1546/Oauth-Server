"use strict";

const express = require("express");
const morgan = require("morgan");
const fs = require("fs");
const _ = require("underscore");
const session = require("express-session");
const randomstring = require("randomstring");
const bodyParser = require("body-parser");

const homePage = _.template(fs.readFileSync("./index.ejs").toString());
const invalidPage = _.template(fs.readFileSync("./invalid.ejs").toString());
const ui = _.template(fs.readFileSync("./input.ejs").toString());

const app = express();
app.use(morgan(":method :url :status Authorization: :req[authorization] Debug info: :res[x-debug] Redirect: :res[location]"));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(session({
  secret: "keyboard cat",
  resave: false,
  saveUninitialized: true,
  cookie: {secure: false}
}))

const EXPECTED_CLIENT_ID = process.env.EXPECTED_CLIENT_ID || "dummy-client-id";
const EXPECTED_CLIENT_SECRET = process.env.EXPECTED_CLIENT_SECRET || "dummy-client-secret";
const AUTH_REQUEST_PATH = process.env.AUTH_REQUEST_PATH || "oauth/login";
const ACCESS_TOKEN_REQUEST_PATH = process.env.ACCESS_TOKEN_REQUEST_PATH || "oauth/token";
const ACCESS_TOKEN_PREFIX = process.env.ACCESS_TOKEN_PREFIX;
const PERMITTED_REDIRECT_URLS = process.env.PERMITTED_REDIRECT_URLS ? 
      process.env.PERMITTED_REDIRECT_URLS.split(",") : 
      ["https://c2c-us.smartthings.com/oauth/callback",
      "https://c2c-eu.smartthings.com/oauth/callback",
      "https://c2c-ap.smartthings.com/oauth/callback",
      "https://c2c-globald.stacceptance.com/oauth/callback",
      "https://c2c-globals.smartthingsgdev.com/oauth/callback",
      "https://c2c-globald.smartthingsgdev.com/oauth/callback",
      "https://c2c-globala.stacceptance.com/oauth/callback",
      "https://api.smartthings.com/oauth/callback"];

const code2token = {};
const refresh2personData = {};
const authHeader2personData = {};
const id_token2personData = {};
let redirect_uri;

function now() {
  return Math.round(new Date().valueOf() / 1000);
}

function errorMsg(descr, expected, actual) {
  return "expected " + descr + ": " + expected + ", actual: " + actual;
}

function validateClientId(actualClientId, res) {
  if (actualClientId === EXPECTED_CLIENT_ID) {
    return true;
  }
  res.writeHead(400, {
    "X-Debug": errorMsg("client_id", EXPECTED_CLIENT_ID, actualClientId)
  });
  res.end();
  return false;
}

function validateAuthorizationHeader(header, res) {
  header = header.trim();
  if (!header.startsWith("Basic ")) {
    return false;
  }
  header = header.substring("Basic ".length).trim();
  const decoded = new Buffer(header, "base64").toString("ascii");
  if (decoded === "") {
    return false;
  }
  const segments = decoded.split(":");
  if (segments.length != 2) {
    return false;
  }
  if (segments[0] !== EXPECTED_CLIENT_ID) {
    return false;
  }
  if (segments[1] !== EXPECTED_CLIENT_SECRET) {
    return false;
  }
  return true;
}

function validateAccessTokenRequest(req, res) {
  let success = true, msg;
  if (req.body.grant_type !== "authorization_code" && req.body.grant_type !== "refresh_token") {
    success = false;
    msg = errorMsg("grant_type", "authorization_code or refresh_token", req.body.grant_type);
  }
  if (req.body.grant_type === "refresh_token") {
    let personData = refresh2personData[req.body.refresh_token];
    if (personData === undefined) {
      success = false;
      msg = "invalid refresh token";
    }
  }
  if (!validateClientId(req.body.client_id, res)) {
    success = false;
  }
  if (req.body.client_secret !== EXPECTED_CLIENT_SECRET) {
    success = false;
    msg = errorMsg("client_secret", EXPECTED_CLIENT_SECRET, req.body.client_secret);
  }
  
  if (redirect_uri !== req.body.redirect_uri) {
    success = false;
    msg = errorMsg("redirect_uri", req.session.redirect_uri, req.body.redirect_uri);
  }
  if (!success) {
    const params = {};
    if (msg) {
      params["X-Debug"] = msg;
    }
    res.writeHead(401, params);
  }
  return success;
}

function createToken(name, email, expires_in, client_state) {
  const code = "C-" + randomstring.generate(3);
  const accesstoken = ACCESS_TOKEN_PREFIX + randomstring.generate(6);
  const refreshtoken = "REFT-" + randomstring.generate(6);
  const id_token = "IDT-" + randomstring.generate(6);
  const token = {
    access_token: accesstoken,
    expires_in: expires_in,
    refresh_token: refreshtoken,
    id_token: id_token,
    state: client_state,
    token_type: "Bearer"
  };
  id_token2personData[id_token] = authHeader2personData["Bearer " + accesstoken] = {
    email: email,
    email_verified: true,
    name: name
  };
  code2token[code] = token;
  refresh2personData[refreshtoken] = {
    name: name,
    email: email,
    expires_in: expires_in
  };
  return code;
}

function validateAuthPageRequest(req, res) {
  const errorMessages = [];
  if (req.query.client_id !== EXPECTED_CLIENT_ID) {
    errorMessages.push(`Invalid client_id, received '${req.query.client_id}'`)
  }

  if (req.query.response_type !== "code") {
    errorMessages.push( `Invalid response type, received '${req.query.response_type}' expected 'code'`)
  }

  if (!(PERMITTED_REDIRECT_URLS.includes(req.query.redirect_uri))) {
    errorMessages.push(`Invalid redirect_uri, received '${req.query.redirect_uri}' expected one of ${PERMITTED_REDIRECT_URLS.join(', ')}`)
  }

  if (errorMessages.length > 0) {
    res.status(401);
    res.send(invalidPage({
      errorMessages: errorMessages
    }));
    return false
  }
  return true
}

app.get('/', (req, res) => {
  res.send(homePage({
    query: req.query
  }));
});

app.get("/oauth/login", (req, res) => {
  if (validateAuthPageRequest(req, res)) {
    req.session.redirect_uri = req.query.redirect_uri;
    redirect_uri = req.query.redirect_uri;
    if (req.query.state) {
      req.session.client_state = req.query.state;
    }
    res.send(ui({
      query: req.query,
      username: `${randomstring.generate(4)}@${randomstring.generate(4)}.com`,
      password: randomstring.generate(4)
    }));
  }
  res.end();
});

app.get("/login-as", (req, res) => {
  const code = createToken(req.query.name, req.query.email, req.query.expires_in, req.session.client_state);
  if (req.session.redirect_uri) {
    let redirectUri = req.session.redirect_uri;
    let location = `${redirectUri}${redirectUri.includes('?') ? '&' : '?'}code=${code}`;
    if (req.session.client_state) {
      location += "&state=" + req.session.client_state;
    }
    res.writeHead(307, {"Location": location});
    res.end();
  }
});

app.post(ACCESS_TOKEN_REQUEST_PATH, (req, res) => {
  if (validateAccessTokenRequest(req, res)) {
    let code = null;
    if (req.body.grant_type === "refresh_token") {
      const refresh = req.body.refresh_token;
      const personData = refresh2personData[refresh];
      code = createToken(personData.name, personData.email, personData.expires_in, null);
      delete refresh2personData[refresh];
    } else {
      code = req.body.code;
    }
    const token = code2token[code];
    if (token !== undefined) {
      console.log("access token response body: ", token);
      res.send(token);
    }
  }
  res.end();
});

module.exports = {
  app: app,
  EXPECTED_CLIENT_ID: EXPECTED_CLIENT_ID,
  EXPECTED_CLIENT_SECRET: EXPECTED_CLIENT_SECRET,
  AUTH_REQUEST_PATH : AUTH_REQUEST_PATH,
  ACCESS_TOKEN_REQUEST_PATH : ACCESS_TOKEN_REQUEST_PATH,
  ACCESS_TOKEN_PREFIX: ACCESS_TOKEN_PREFIX
};

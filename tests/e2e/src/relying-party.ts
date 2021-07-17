// Starts a simple relying party implementation.

import express, { Request, Response } from "express";
import fetch from "node-fetch";
import querystring from "querystring";
import { EventEmitter } from "events";
import { PortierClient } from "portier";
import { urlencoded as createFormParser } from "body-parser";

const formParser = createFormParser({ extended: false });

export type RelyingParty = EventEmitter & {
  portier: PortierClient;
  destroy(): void;
};

export default (): RelyingParty => {
  const emitter = new EventEmitter();

  const portier = new PortierClient({
    broker: "http://localhost:44133",
    redirectUri: "http://localhost:44180/verify",
  });

  const app = express();

  app.get("/", (_req, res) => {
    res.type("html").end(`
      <title>RP: Login</title>
      <form method="post" action="/auth">
        <input name="email" type="email">
      </form>
    `);
  });

  app.post("/auth", formParser, async (req, res) => {
    let authUrl;
    try {
      authUrl = await portier.authenticate(req.body.email);
    } catch (err) {
      console.error("RP failed to start authentication:");
      console.error(err);
      return res.status(500).type("html").end(`
        <title>RP: Error</title>
      `);
    }

    res.redirect(303, authUrl);
  });

  app.get("/verify", verifyHandler);
  app.post("/verify", formParser, verifyHandler);
  async function verifyHandler(req: Request, res: Response) {
    const params = req.body || req.query;
    if (params.error) {
      if (!emitter.emit("gotError", params)) {
        console.error(`RP got an error from the broker: ${params.error}`);
        console.error(`Description: ${params.error_description}`);
      }
      return res.status(500).type("html").end(`
        <title>RP: Got error</title>
      `);
    }

    // For testing the authorization code flow.
    let token = params.id_token || "";
    if (!token && params.code) {
      const tokenRes = await fetch("http://localhost:44133/token", {
        method: "POST",
        body: querystring.stringify({
          grant_type: "authorization_code",
          code: params.code,
          redirect_uri: portier.redirectUri,
        }),
      });
      const body = await tokenRes.json();
      if (tokenRes.status !== 200) {
        if (!emitter.emit("gotError", params)) {
          console.error(`RP got an error from the broker: ${body.error}`);
          console.error(`Description: ${body.error_description}`);
        }
        return res.status(500).type("html").end(`
          <title>RP: Got error</title>
        `);
      }
      token = body.id_token || "";
    }

    let email;
    try {
      email = await portier.verify(token);
    } catch (err) {
      if (!emitter.emit("invalidToken", params)) {
        console.error("RP failed to verify token:");
        console.error(err);
      }
      return res.status(500).type("html").end(`
        <title>RP: Invalid token</title>
      `);
    }

    res.type("html").end(`
      <title>RP: Confirmed</title>
      <p>${email}</p>
    `);
  }

  const server = app.listen(44180, "localhost");

  return Object.assign(emitter, {
    portier,
    destroy: () => {
      server.close();
      portier.destroy();
    },
  });
};

// The main test suite.

import assert from "assert";
import { By, Key, until, WebDriver } from "selenium-webdriver";
import { Mailbox } from "./mailbox";
import { Broker } from "./broker";
import { RelyingParty } from "./relying-party";
import { HttpMailer } from "./http-mailer";

import { TEST_MAILER } from "./env";

export interface TestContext {
  mailbox: Mailbox;
  broker: Broker;
  relyingParty: RelyingParty;
  httpMailer: HttpMailer;
  driver: WebDriver;
}

const ALL_TESTS: { name: string; fn: (ctx: TestContext) => void }[] = [];
const test = (name: string, fn: (ctx: TestContext) => void) =>
  ALL_TESTS.push({ name, fn });
const postmarkTest = (name: string, fn: (ctx: TestContext) => void) =>
  TEST_MAILER === "postmark" && test(`postmark -> ${name}`, fn);
const mailgunTest = (name: string, fn: (ctx: TestContext) => void) =>
  TEST_MAILER === "mailgun" && test(`mailgun -> ${name}`, fn);

const TIMEOUT = 10000;
const OVERALL_TIMEOUT = 30000;
const JOHN_EMAIL = "john.doe@example.com";
const BROKER_CONFIRM_TITLE = "Portier – Confirm your address";
const BROKER_ERROR_TITLE = "Portier – Error";
const RP_LOGIN_TITLE = "RP: Login";
const RP_CONFIRMED_TITLE = "RP: Confirmed";
const RP_GOT_ERROR_TITLE = "RP: Got error";

test("successful flow with code input", async ({ mailbox, driver }) => {
  await driver.get("http://localhost:44180/");
  await driver.wait(until.titleIs(RP_LOGIN_TITLE), TIMEOUT);

  const emailInput = await driver.findElement(By.name("email"));
  await emailInput.sendKeys(JOHN_EMAIL, Key.RETURN);
  await driver.wait(until.titleIs(BROKER_CONFIRM_TITLE), TIMEOUT);

  const mail = mailbox.nextMail();
  const match = /^[a-z0-9]{6} [a-z0-9]{6}$/m.exec(mail ?? "");
  if (!match) {
    throw Error("Could not find the verification code in the email text");
  }
  const code = match[0];

  const codeInput = await driver.findElement(By.name("code"));
  await codeInput.sendKeys(code, Key.RETURN);
  await driver.wait(until.titleIs(RP_CONFIRMED_TITLE), TIMEOUT);

  const textElement = await driver.findElement(By.css("p"));
  const text = await textElement.getText();
  assert.strictEqual(text, JOHN_EMAIL);
});

test("successful flow following the email link", async ({
  mailbox,
  driver,
}) => {
  await driver.get("http://localhost:44180/");
  await driver.wait(until.titleIs(RP_LOGIN_TITLE), TIMEOUT);

  const emailInput = await driver.findElement(By.name("email"));
  await emailInput.sendKeys(JOHN_EMAIL, Key.RETURN);
  await driver.wait(until.titleIs(BROKER_CONFIRM_TITLE), TIMEOUT);

  const mail = mailbox.nextMail();
  const match = /^http:\/\/localhost:44133\/confirm\?.+$/m.exec(mail ?? "");
  if (!match) {
    throw Error("Could not find the confirmation URL in the email text");
  }
  const url = match[0];

  await driver.get(url);
  await driver.wait(until.titleIs(RP_CONFIRMED_TITLE), TIMEOUT);

  const textElement = await driver.findElement(By.css("p"));
  const text = await textElement.getText();
  assert.strictEqual(text, JOHN_EMAIL);

  // Ensure the link no longer works.
  await driver.get(url);
  await driver.wait(until.titleIs(BROKER_ERROR_TITLE), TIMEOUT);

  const introElement = await driver.findElement(By.className("head"));
  const intro = await introElement.getText();
  assert.strictEqual(intro, "The session has expired.");
});

test("successful flow with authorization code", async ({
  mailbox,
  relyingParty,
  driver,
}) => {
  const authUrl = (await relyingParty.portier.authenticate(JOHN_EMAIL))
    .replace(/response_type=id_token/, "response_type=code")
    .replace(/response_mode=form_post/, "");

  await driver.get(authUrl);
  await driver.wait(until.titleIs(BROKER_CONFIRM_TITLE), TIMEOUT);

  const mail = mailbox.nextMail();
  const match = /^[a-z0-9]{6} [a-z0-9]{6}$/m.exec(mail ?? "");
  if (!match) {
    throw Error("Could not find the verification code in the email text");
  }
  const code = match[0];

  const codeInput = await driver.findElement(By.name("code"));
  await codeInput.sendKeys(code, Key.RETURN);
  await driver.wait(until.titleIs(RP_CONFIRMED_TITLE), TIMEOUT);

  const textElement = await driver.findElement(By.css("p"));
  const text = await textElement.getText();
  assert.strictEqual(text, JOHN_EMAIL);
});

test("can omit email scope", async ({ driver, relyingParty }) => {
  let authUrl = await relyingParty.portier.authenticate(JOHN_EMAIL);
  authUrl = authUrl.replace(/scope=openid%20email/, "scope=openid");

  await driver.get(authUrl);
  await driver.wait(until.titleIs(BROKER_CONFIRM_TITLE), TIMEOUT);
});

test("cannot omit openid scope", async ({ driver, relyingParty }) => {
  let authUrl = await relyingParty.portier.authenticate(JOHN_EMAIL);
  authUrl = authUrl.replace(/scope=openid%20email/, "scope=email");

  relyingParty.on("gotError", (body) => {
    assert.strictEqual(
      body.error_description,
      "unsupported scope, must contain 'openid'"
    );
  });
  await driver.get(authUrl);
  await driver.wait(until.titleIs(RP_GOT_ERROR_TITLE), TIMEOUT);
});

postmarkTest("sends API request", async ({ httpMailer, driver }) => {
  await driver.get("http://localhost:44180/");
  await driver.wait(until.titleIs(RP_LOGIN_TITLE), TIMEOUT);

  const emailInput = await driver.findElement(By.name("email"));
  await emailInput.sendKeys(JOHN_EMAIL, Key.RETURN);
  await driver.wait(until.titleIs(BROKER_CONFIRM_TITLE), TIMEOUT);

  const requests = httpMailer.getRequests();
  assert.strictEqual(requests.length, 1);
  assert.strictEqual(requests[0].body["To"], JOHN_EMAIL);
});

mailgunTest("sends API request", async ({ httpMailer, driver }) => {
  await driver.get("http://localhost:44180/");
  await driver.wait(until.titleIs(RP_LOGIN_TITLE), TIMEOUT);

  const emailInput = await driver.findElement(By.name("email"));
  await emailInput.sendKeys(JOHN_EMAIL, Key.RETURN);
  await driver.wait(until.titleIs(BROKER_CONFIRM_TITLE), TIMEOUT);

  const requests = httpMailer.getRequests();
  assert.strictEqual(requests.length, 1);
  assert.strictEqual(
    Object.prototype.hasOwnProperty.call(requests[0].body, "to"),
    true
  );
  assert.strictEqual(requests[0].body["to"], JOHN_EMAIL);
  assert.strictEqual(
    Object.prototype.hasOwnProperty.call(requests[0].body, "from"),
    true
  );
  assert.strictEqual(
    Object.prototype.hasOwnProperty.call(requests[0].body, "subject"),
    true
  );
  assert.strictEqual(
    Object.prototype.hasOwnProperty.call(requests[0].body, "html"),
    true
  );
  assert.strictEqual(
    Object.prototype.hasOwnProperty.call(requests[0].body, "text"),
    true
  );
});

export default async (ctx: TestContext) => {
  for (const { name, fn } of ALL_TESTS) {
    // Preparation.
    ctx.relyingParty.removeAllListeners();
    ctx.mailbox.clearMail();
    ctx.httpMailer.clearRequests();
    // Run test and apply a timeout.
    try {
      const timeout = new Promise((_resolve, reject) =>
        setTimeout(() => {
          reject(Error("Test timed out"));
        }, OVERALL_TIMEOUT).unref()
      );
      await Promise.race([timeout, fn(ctx)]);
    } catch (err) {
      console.error(` ✖ ${name}`);
      console.error(err);
      process.exitCode = 1;
      continue;
    }
    console.error(` ✔ ${name}`);
  }
};

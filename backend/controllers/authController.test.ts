import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import bcrypt from 'bcryptjs';
import type { Request, Response } from 'express';
import { after, before, test } from 'node:test';
import { createRateLimiter } from '../middleware/rateLimitMiddleware.ts';

type AuthHandler = (req: Request, res: Response) => Promise<void>;
type StoreModule = typeof import('../config/store.ts');
type AuthResponseBody = {
  message?: string;
  email?: string;
  needsVerification?: boolean;
  token?: string;
  user?: { email: string; role: string; username?: string };
};

let loginUser: AuthHandler;
let registerUser: AuthHandler;
let getJwtSecret: typeof import('../middleware/authMiddleware.ts').getJwtSecret;
let store: StoreModule;
let originalCwd: string;
let testCwd: string;

before(async () => {
  originalCwd = process.cwd();
  testCwd = mkdtempSync(path.join(tmpdir(), 'bookhaven-auth-'));
  process.chdir(testCwd);
  ({ loginUser, registerUser } = await import('./authController.ts'));
  ({ getJwtSecret } = await import('../middleware/authMiddleware.ts'));
  store = await import('../config/store.ts');
});

after(() => {
  process.chdir(originalCwd);
  rmSync(testCwd, { recursive: true, force: true });
});

async function callAuthHandler(
  handler: AuthHandler,
  body: Record<string, string>
): Promise<{ status: number; body: AuthResponseBody }> {
  let status = 200;
  let responseBody: unknown;
  const response = {
    status(code: number) {
      status = code;
      return response;
    },
    json(value: unknown) {
      responseBody = value;
      return response;
    },
  };

  await handler({ body } as Request, response as unknown as Response);
  return { status, body: responseBody as AuthResponseBody };
}

async function addLocalUser(
  email: string,
  username: string | undefined,
  password: string,
  isVerified: boolean
): Promise<void> {
  const passwordHash = await bcrypt.hash(password, 10);
  await store.runStoreTransaction((db) => {
    const user = {
      ...db.users[0],
      _id: store.generateObjectId(),
      name: 'Test Reader',
      email,
      password: passwordHash,
      isVerified,
      otpHash: null,
      otpExpires: null,
      otpLastSentAt: null,
      otpAttempts: 0,
      otpLockedUntil: null,
      wishlist: [],
    };
    if (username) user.username = username;
    else delete user.username;
    db.users.push(user);
  });
}

test('customers can sign in with email or a case-insensitive username', async () => {
  const byEmail = await callAuthHandler(loginUser, {
    identifier: 'AYE@BOOKHAVEN.MM',
    password: 'Customer123!',
  });
  const byUsername = await callAuthHandler(loginUser, {
    identifier: 'AyeChanMoe',
    password: 'Customer123!',
  });
  const legacyEmailRequest = await callAuthHandler(loginUser, {
    email: 'aye@bookhaven.mm',
    password: 'Customer123!',
  });

  assert.equal(byEmail.status, 200);
  assert.equal(byEmail.body.user?.role, 'customer');
  assert.equal(byUsername.status, 200);
  assert.equal(byUsername.body.user?.email, 'aye@bookhaven.mm');
  assert.equal(legacyEmailRequest.status, 200);
  assert.equal(
    Object.prototype.hasOwnProperty.call(byEmail.body.user ?? {}, 'password'),
    false
  );
});

test('admin can sign in with username and retains the admin role', async () => {
  const result = await callAuthHandler(loginUser, {
    identifier: 'ADMIN',
    password: 'Admin123!',
  });

  assert.equal(result.status, 200);
  assert.equal(result.body.user?.role, 'admin');
});

test('incorrect credentials are rejected', async () => {
  const result = await callAuthHandler(loginUser, {
    identifier: 'ayechanmoe',
    password: 'incorrect-password',
  });

  assert.equal(result.status, 401);
  assert.equal(result.body.message, 'Invalid email/username or password.');
});

test('invalid identifiers receive the same authentication error', async () => {
  const result = await callAuthHandler(loginUser, {
    identifier: 'not-a-user',
    password: 'Customer123!',
  });

  assert.equal(result.status, 401);
  assert.equal(result.body.message, 'Invalid email/username or password.');
});

test('login requires a non-empty identifier and password', async () => {
  const result = await callAuthHandler(loginUser, {
    identifier: '',
    password: 'Customer123!',
  });

  assert.equal(result.status, 400);
  assert.equal(result.body.message, 'Please enter an email or username and password.');
});

test('legacy users without usernames can still sign in by email', async () => {
  await addLocalUser('legacy@example.com', undefined, 'Legacy123!', true);

  const result = await callAuthHandler(loginUser, {
    identifier: 'LEGACY@EXAMPLE.COM',
    password: 'Legacy123!',
  });

  assert.equal(result.status, 200);
  assert.equal(result.body.user?.email, 'legacy@example.com');
  assert.equal(result.body.user?.username, undefined);
});

test('unverified users are directed to OTP verification by their email', async () => {
  await addLocalUser('pending@example.com', 'pending.reader', 'Pending123!', false);

  const result = await callAuthHandler(loginUser, {
    identifier: 'PENDING.READER',
    password: 'Pending123!',
  });

  assert.equal(result.status, 403);
  assert.equal(result.body.needsVerification, true);
  assert.equal(result.body.email, 'pending@example.com');
});

test('registration rejects duplicate usernames case-insensitively', async () => {
  const result = await callAuthHandler(registerUser, {
    name: 'New Reader',
    username: 'AYECHANMOE',
    email: 'new-reader@example.com',
    password: 'Reader123!',
    confirmPassword: 'Reader123!',
  });

  assert.equal(result.status, 409);
  assert.equal(result.body.message, 'This username is already taken.');
});

test('registration rejects duplicate email addresses case-insensitively', async () => {
  const result = await callAuthHandler(registerUser, {
    name: 'Existing Reader',
    username: 'newreader',
    email: 'AYE@BOOKHAVEN.MM',
    password: 'Reader123!',
    confirmPassword: 'Reader123!',
  });

  assert.equal(result.status, 409);
  assert.equal(result.body.message, 'An account with this email already exists.');
});

test('registration requires matching password confirmation', async () => {
  const result = await callAuthHandler(registerUser, {
    name: 'New Reader',
    username: 'newreader',
    email: 'new-reader@example.com',
    password: 'Reader123!',
    confirmPassword: 'Different123!',
  });

  assert.equal(result.status, 400);
  assert.equal(result.body.message, 'Passwords do not match.');
});

test('login rate limiting cannot be bypassed by changing identifiers from the same IP', () => {
  const limiter = createRateLimiter({
    windowMs: 60_000,
    maxRequests: 1,
    keyPrefix: 'login-test',
    message: 'Too many sign-in attempts.',
    keyByIpOnly: true,
  });
  let allowedRequests = 0;
  let blockedStatus = 0;

  const makeRequest = (identifier: string) =>
    ({
      ip: '127.0.0.1',
      socket: { remoteAddress: '127.0.0.1' },
      body: { identifier },
    }) as Request;
  const response = {
    setHeader() {
      return response;
    },
    status(code: number) {
      blockedStatus = code;
      return response;
    },
    json() {
      return response;
    },
  } as unknown as Response;

  limiter(makeRequest('first-user'), response, () => {
    allowedRequests += 1;
  });
  limiter(makeRequest('different-user'), response, () => {
    allowedRequests += 1;
  });

  assert.equal(allowedRequests, 1);
  assert.equal(blockedStatus, 429);
});

test('production authentication requires an explicit JWT secret', () => {
  const originalNodeEnv = process.env.NODE_ENV;
  const originalJwtSecret = process.env.JWT_SECRET;
  process.env.NODE_ENV = 'production';
  delete process.env.JWT_SECRET;

  try {
    assert.throws(() => getJwtSecret(), /JWT_SECRET must be configured/);
  } finally {
    if (originalNodeEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = originalNodeEnv;
    if (originalJwtSecret === undefined) delete process.env.JWT_SECRET;
    else process.env.JWT_SECRET = originalJwtSecret;
  }
});


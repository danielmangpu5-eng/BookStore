import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import { Request, Response } from 'express';
import mongoose from 'mongoose';
import { isMongoConnected } from '../config/db.ts';
import { generateObjectId, loadStore, runStoreTransaction } from '../config/store.ts';
import { AuthenticatedRequest, signAuthToken } from '../middleware/authMiddleware.ts';
import { UserModel } from '../models/User.ts';
import { sendOtpEmail } from '../utils/sendEmail.ts';

const OTP_EXPIRY_MS = 5 * 60 * 1000; // 5 minutes
const RESEND_COOLDOWN_MS = 60 * 1000; // 60 seconds
const MAX_OTP_ATTEMPTS = 5;
const OTP_LOCKOUT_MS = 15 * 60 * 1000; // 15 minutes
const DUMMY_PASSWORD_HASH = bcrypt.hashSync('bookhaven-invalid-login', 10);

function generateSixDigitOtp(): string {
  return crypto.randomInt(0, 1000000).toString().padStart(6, '0');
}

export async function registerUser(req: Request, res: Response): Promise<void> {
  try {
    const { name, username, email, password, confirmPassword } = req.body as {
      name?: string;
      username?: string;
      email?: string;
      password?: string;
      confirmPassword?: string;
    };

    if (typeof name !== 'string' || name.trim().length < 2) {
      res.status(400).json({ message: 'Please enter your full name (at least 2 characters).' });
      return;
    }
    if (typeof email !== 'string' || !/^\S+@\S+\.\S+$/.test(email.trim())) {
      res.status(400).json({ message: 'Please provide a valid email address.' });
      return;
    }
    if (typeof username !== 'string' || !/^[a-zA-Z0-9._-]{3,30}$/.test(username.trim())) {
      res.status(400).json({
        message: 'Username must be 3-30 characters and contain only letters, numbers, dots, underscores, or hyphens.',
      });
      return;
    }
    if (typeof password !== 'string' || password.length < 6) {
      res.status(400).json({ message: 'Password must be at least 6 characters.' });
      return;
    }
    if (typeof confirmPassword !== 'string' || confirmPassword !== password) {
      res.status(400).json({ message: 'Passwords do not match.' });
      return;
    }

    const normalizedEmail = email.trim().toLowerCase();
    const normalizedUsername = username.trim().toLowerCase();
    const trimmedName = name.trim();
    const now = Date.now();

    if (isMongoConnected()) {
      const existing = await UserModel.findOne({ email: normalizedEmail })
        .collation({ locale: 'en', strength: 2 })
        .select('+otpLastSentAt +otpLockedUntil');

      if (existing && existing.isVerified) {
        res.status(409).json({ message: 'An account with this email already exists.' });
        return;
      }

      const usernameOwner = await UserModel.findOne({
        username: normalizedUsername,
        email: { $ne: normalizedEmail },
      })
        .collation({ locale: 'en', strength: 2 })
        .select('_id');
      if (usernameOwner) {
        res.status(409).json({ message: 'This username is already taken.' });
        return;
      }

      if (existing?.otpLockedUntil && existing.otpLockedUntil.getTime() > now) {
        const waitMinutes = Math.ceil((existing.otpLockedUntil.getTime() - now) / 60000);
        res.status(429).json({
          message: `Verification is temporarily locked due to too many failed attempts. Try again in ${waitMinutes} minute(s).`,
        });
        return;
      }

      if (existing?.otpLastSentAt && now - existing.otpLastSentAt.getTime() < RESEND_COOLDOWN_MS) {
        const retryAfterSeconds = Math.ceil(
          (RESEND_COOLDOWN_MS - (now - existing.otpLastSentAt.getTime())) / 1000
        );
        res.status(429).json({
          message: `Please wait ${retryAfterSeconds}s before requesting another verification code.`,
          retryAfterSeconds,
        });
        return;
      }

      const otp = generateSixDigitOtp();
      const otpHash = await bcrypt.hash(otp, 10);
      const otpExpires = new Date(now + OTP_EXPIRY_MS);
      const otpLastSentAt = new Date(now);

      // Deliver email first so failed email configuration/delivery never leaves a cooldown lock
      await sendOtpEmail(normalizedEmail, trimmedName, otp);

      if (existing && !existing.isVerified) {
        existing.name = trimmedName;
        existing.username = normalizedUsername;
        existing.password = password;
        existing.otpHash = otpHash;
        existing.otpExpires = otpExpires;
        existing.otpLastSentAt = otpLastSentAt;
        existing.otpAttempts = 0;
        existing.otpLockedUntil = null;
        await existing.save();
      } else {
        await UserModel.create({
          name: trimmedName,
          username: normalizedUsername,
          email: normalizedEmail,
          password,
          role: 'customer',
          isVerified: false,
          otpHash,
          otpExpires,
          otpLastSentAt,
          otpAttempts: 0,
          otpLockedUntil: null,
        });
      }

      res.status(201).json({
        message: 'Verification code sent to your email. Please check your inbox (expires in 5 minutes).',
        email: normalizedEmail,
        cooldownSeconds: 60,
        expiresInSeconds: 300,
      });
      return;
    }

    // Local transactional store validation before sending email
    const dbSnapshot = loadStore();
    const existingLocal = dbSnapshot.users.find(
      (u) => u.email.trim().toLowerCase() === normalizedEmail
    );
    if (existingLocal && existingLocal.isVerified) {
      res.status(409).json({ message: 'An account with this email already exists.' });
      return;
    }
    const usernameOwnerLocal = dbSnapshot.users.find(
      (u) =>
        u.username?.trim().toLowerCase() === normalizedUsername &&
        u.email.trim().toLowerCase() !== normalizedEmail
    );
    if (usernameOwnerLocal) {
      res.status(409).json({ message: 'This username is already taken.' });
      return;
    }
    if (existingLocal?.otpLockedUntil && new Date(existingLocal.otpLockedUntil).getTime() > now) {
      const waitMinutes = Math.ceil(
        (new Date(existingLocal.otpLockedUntil).getTime() - now) / 60000
      );
      res.status(429).json({
        message: `Verification is temporarily locked due to too many failed attempts. Try again in ${waitMinutes} minute(s).`,
      });
      return;
    }
    if (
      existingLocal?.otpLastSentAt &&
      now - new Date(existingLocal.otpLastSentAt).getTime() < RESEND_COOLDOWN_MS
    ) {
      const retryAfterSeconds = Math.ceil(
        (RESEND_COOLDOWN_MS - (now - new Date(existingLocal.otpLastSentAt).getTime())) / 1000
      );
      res.status(429).json({
        message: `Please wait ${retryAfterSeconds}s before requesting another verification code.`,
        retryAfterSeconds,
      });
      return;
    }

    const otp = generateSixDigitOtp();
    const otpHash = await bcrypt.hash(otp, 10);
    const otpExpiresIso = new Date(now + OTP_EXPIRY_MS).toISOString();
    const otpLastSentIso = new Date(now).toISOString();

    await sendOtpEmail(normalizedEmail, trimmedName, otp);

    await runStoreTransaction(async (db) => {
      const existing = db.users.find((u) => u.email.trim().toLowerCase() === normalizedEmail);
      if (existing && existing.isVerified) {
        const err = new Error('An account with this email already exists.') as Error & { status?: number };
        err.status = 409;
        throw err;
      }
      const usernameOwner = db.users.find(
        (u) =>
          u.username?.trim().toLowerCase() === normalizedUsername &&
          u.email.trim().toLowerCase() !== normalizedEmail
      );
      if (usernameOwner) {
        const err = new Error('This username is already taken.') as Error & { status?: number };
        err.status = 409;
        throw err;
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      const nowIso = new Date(now).toISOString();

      if (existing && !existing.isVerified) {
        existing.name = trimmedName;
        existing.username = normalizedUsername;
        existing.password = hashedPassword;
        existing.otpHash = otpHash;
        existing.otpExpires = otpExpiresIso;
        existing.otpLastSentAt = otpLastSentIso;
        existing.otpAttempts = 0;
        existing.otpLockedUntil = null;
        existing.updatedAt = nowIso;
      } else {
        db.users.push({
          _id: generateObjectId(),
          name: trimmedName,
          username: normalizedUsername,
          email: normalizedEmail,
          password: hashedPassword,
          role: 'customer',
          isVerified: false,
          otpHash,
          otpExpires: otpExpiresIso,
          otpLastSentAt: otpLastSentIso,
          otpAttempts: 0,
          otpLockedUntil: null,
          wishlist: [],
          shippingAddress: {
            fullName: trimmedName,
            phone: '',
            streetAddress: '',
            township: '',
            city: 'Yangon',
            postalCode: '11181',
          },
          createdAt: nowIso,
          updatedAt: nowIso,
        });
      }
    });

    res.status(201).json({
      message: 'Verification code sent to your email. Please check your inbox (expires in 5 minutes).',
      email: normalizedEmail,
      cooldownSeconds: 60,
      expiresInSeconds: 300,
    });
  } catch (err) {
    const error = err as Error & {
      status?: number;
      code?: number | string;
      keyPattern?: Record<string, number>;
    };
    if (error.code === 11000) {
      const duplicateField = error.keyPattern?.username
        ? 'username'
        : error.keyPattern?.email
          ? 'email'
          : null;
      res.status(409).json({
        message:
          duplicateField === 'username'
            ? 'This username is already taken.'
            : duplicateField === 'email'
              ? 'An account with this email already exists.'
              : 'An account with this email or username already exists.',
      });
      return;
    }
    res.status(error.status || 500).json({
      message: error.message || 'Registration failed.',
      code: typeof error.code === 'string' ? error.code : undefined,
    });
  }
}

export async function verifyOtp(req: Request, res: Response): Promise<void> {
  try {
    const { email, otp } = req.body as { email?: string; otp?: string };

    if (!email || !otp || !/^\d{6}$/.test(otp.trim())) {
      res.status(400).json({ message: 'Please provide your email and a valid 6-digit OTP code.' });
      return;
    }

    const normalizedEmail = email.trim().toLowerCase();
    const cleanOtp = otp.trim();
    const now = Date.now();

    if (isMongoConnected()) {
      const user = await UserModel.findOne({ email: normalizedEmail })
        .collation({ locale: 'en', strength: 2 })
        .select('+otpHash +otpExpires +otpAttempts +otpLockedUntil');
      if (!user) {
        res.status(404).json({ message: 'Account not found.' });
        return;
      }
      if (user.isVerified) {
        res.status(400).json({ message: 'Account is already verified. Please sign in.' });
        return;
      }
      if (user.otpLockedUntil && user.otpLockedUntil.getTime() > now) {
        const waitMinutes = Math.ceil((user.otpLockedUntil.getTime() - now) / 60000);
        res.status(429).json({
          message: `Too many incorrect verification attempts. Please wait ${waitMinutes} minute(s) before trying again.`,
        });
        return;
      }
      if (!user.otpHash || !user.otpExpires) {
        res.status(400).json({ message: 'No active verification code found. Please request a new code.' });
        return;
      }
      if (user.otpExpires.getTime() < now) {
        user.otpHash = null;
        user.otpExpires = null;
        await user.save();
        res.status(400).json({ message: 'Verification code has expired. Please request a new code.' });
        return;
      }

      const isMatch = await bcrypt.compare(cleanOtp, user.otpHash);
      if (!isMatch) {
        user.otpAttempts = (user.otpAttempts || 0) + 1;
        if (user.otpAttempts >= MAX_OTP_ATTEMPTS) {
          user.otpLockedUntil = new Date(now + OTP_LOCKOUT_MS);
          user.otpHash = null;
          user.otpExpires = null;
          await user.save();
          res.status(429).json({
            message: 'Too many incorrect verification attempts. Verification has been locked for 15 minutes.',
          });
          return;
        }
        await user.save();
        const remaining = MAX_OTP_ATTEMPTS - user.otpAttempts;
        res.status(400).json({
          message: `Invalid 6-digit verification code. ${remaining} attempt(s) remaining.`,
        });
        return;
      }

      // Invalidate OTP and activate account
      user.isVerified = true;
      user.otpHash = null;
      user.otpExpires = null;
      user.otpLastSentAt = null;
      user.otpAttempts = 0;
      user.otpLockedUntil = null;
      await user.save();

      const token = signAuthToken({
        id: user._id.toString(),
        name: user.name,
        email: user.email,
        role: user.role,
        isVerified: true,
      });

      res.json({
        message: 'Email verified successfully.',
        token,
        user: {
          id: user._id.toString(),
          name: user.name,
          username: user.username,
          email: user.email,
          role: user.role,
          isVerified: user.isVerified,
          wishlist: user.wishlist.map((id) => id.toString()),
          shippingAddress: user.shippingAddress,
        },
      });
      return;
    }

    const dbCheck = loadStore();
    const candidate = dbCheck.users.find(
      (u) => u.email.trim().toLowerCase() === normalizedEmail
    );
    if (!candidate) {
      res.status(404).json({ message: 'Account not found.' });
      return;
    }
    if (candidate.isVerified) {
      res.status(400).json({ message: 'Account is already verified. Please sign in.' });
      return;
    }
    if (candidate.otpLockedUntil && new Date(candidate.otpLockedUntil).getTime() > now) {
      const waitMinutes = Math.ceil((new Date(candidate.otpLockedUntil).getTime() - now) / 60000);
      res.status(429).json({
        message: `Too many incorrect verification attempts. Please wait ${waitMinutes} minute(s) before trying again.`,
      });
      return;
    }
    if (!candidate.otpHash || !candidate.otpExpires) {
      res.status(400).json({ message: 'No active verification code found. Please request a new code.' });
      return;
    }

    if (new Date(candidate.otpExpires).getTime() < now) {
      await runStoreTransaction((db) => {
        const user = db.users.find(
          (u) => u.email.trim().toLowerCase() === normalizedEmail
        );
        if (user) {
          user.otpHash = null;
          user.otpExpires = null;
          user.updatedAt = new Date(now).toISOString();
        }
      });
      res.status(400).json({ message: 'Verification code has expired. Please request a new code.' });
      return;
    }

    const isMatch = await bcrypt.compare(cleanOtp, candidate.otpHash);
    if (!isMatch) {
      const attemptResult = await runStoreTransaction((db) => {
        const user = db.users.find(
          (u) => u.email.trim().toLowerCase() === normalizedEmail
        );
        if (!user) return { locked: false, remaining: 0 };
        user.otpAttempts = (user.otpAttempts || 0) + 1;
        user.updatedAt = new Date(now).toISOString();
        if (user.otpAttempts >= MAX_OTP_ATTEMPTS) {
          user.otpLockedUntil = new Date(now + OTP_LOCKOUT_MS).toISOString();
          user.otpHash = null;
          user.otpExpires = null;
          return { locked: true, remaining: 0 };
        }
        return { locked: false, remaining: MAX_OTP_ATTEMPTS - user.otpAttempts };
      });

      if (attemptResult.locked) {
        res.status(429).json({
          message: 'Too many incorrect verification attempts. Verification has been locked for 15 minutes.',
        });
        return;
      }

      res.status(400).json({
        message: `Invalid 6-digit verification code. ${attemptResult.remaining} attempt(s) remaining.`,
      });
      return;
    }

    const verifiedUser = await runStoreTransaction((db) => {
      const user = db.users.find(
        (u) => u.email.trim().toLowerCase() === normalizedEmail
      );
      if (!user) {
        const err = new Error('Account not found.') as Error & { status?: number };
        err.status = 404;
        throw err;
      }
      user.isVerified = true;
      user.otpHash = null;
      user.otpExpires = null;
      user.otpLastSentAt = null;
      user.otpAttempts = 0;
      user.otpLockedUntil = null;
      user.updatedAt = new Date(now).toISOString();
      return user;
    });

    const token = signAuthToken({
      id: verifiedUser._id,
      name: verifiedUser.name,
      email: verifiedUser.email,
      role: verifiedUser.role,
      isVerified: true,
    });

    res.json({
      message: 'Email verified successfully.',
      token,
      user: {
        id: verifiedUser._id,
        name: verifiedUser.name,
        username: verifiedUser.username,
        email: verifiedUser.email,
        role: verifiedUser.role,
        isVerified: verifiedUser.isVerified,
        wishlist: verifiedUser.wishlist,
        shippingAddress: verifiedUser.shippingAddress,
      },
    });
  } catch (err) {
    const error = err as Error & { status?: number };
    res.status(error.status || 500).json({ message: error.message || 'OTP verification failed.' });
  }
}

export async function resendOtp(req: Request, res: Response): Promise<void> {
  try {
    const { email } = req.body as { email?: string };
    if (!email) {
      res.status(400).json({ message: 'Email address is required.' });
      return;
    }

    const normalizedEmail = email.trim().toLowerCase();
    const now = Date.now();
    const otp = generateSixDigitOtp();
    const otpHash = await bcrypt.hash(otp, 10);
    const otpExpires = new Date(now + OTP_EXPIRY_MS);
    const otpLastSentAt = new Date(now);

    if (isMongoConnected()) {
      const user = await UserModel.findOne({ email: normalizedEmail })
        .collation({ locale: 'en', strength: 2 })
        .select('+otpLastSentAt +otpLockedUntil');
      if (!user) {
        res.status(404).json({ message: 'No account found with this email.' });
        return;
      }
      if (user.isVerified) {
        res.status(400).json({ message: 'Account is already verified.' });
        return;
      }
      if (user.otpLockedUntil && user.otpLockedUntil.getTime() > now) {
        const waitMinutes = Math.ceil((user.otpLockedUntil.getTime() - now) / 60000);
        res.status(429).json({
          message: `Verification is temporarily locked due to too many failed attempts. Try again in ${waitMinutes} minute(s).`,
        });
        return;
      }
      if (user.otpLastSentAt && now - user.otpLastSentAt.getTime() < RESEND_COOLDOWN_MS) {
        const retryAfterSeconds = Math.ceil(
          (RESEND_COOLDOWN_MS - (now - user.otpLastSentAt.getTime())) / 1000
        );
        res.status(429).json({
          message: `Please wait ${retryAfterSeconds}s before requesting another verification code.`,
          retryAfterSeconds,
        });
        return;
      }

      await sendOtpEmail(normalizedEmail, user.name, otp);

      user.otpHash = otpHash;
      user.otpExpires = otpExpires;
      user.otpLastSentAt = otpLastSentAt;
      user.otpAttempts = 0;
      await user.save();

      res.json({
        message: 'A new 6-digit verification code has been sent to your email.',
        cooldownSeconds: 60,
        expiresInSeconds: 300,
      });
      return;
    }

    const dbSnapshot = loadStore();
    const userLocal = dbSnapshot.users.find(
      (u) => u.email.trim().toLowerCase() === normalizedEmail
    );
    if (!userLocal) {
      res.status(404).json({ message: 'No account found with this email.' });
      return;
    }
    if (userLocal.isVerified) {
      res.status(400).json({ message: 'Account is already verified.' });
      return;
    }
    if (userLocal.otpLockedUntil && new Date(userLocal.otpLockedUntil).getTime() > now) {
      const waitMinutes = Math.ceil((new Date(userLocal.otpLockedUntil).getTime() - now) / 60000);
      res.status(429).json({
        message: `Verification is temporarily locked due to too many failed attempts. Try again in ${waitMinutes} minute(s).`,
      });
      return;
    }
    if (
      userLocal.otpLastSentAt &&
      now - new Date(userLocal.otpLastSentAt).getTime() < RESEND_COOLDOWN_MS
    ) {
      const retryAfterSeconds = Math.ceil(
        (RESEND_COOLDOWN_MS - (now - new Date(userLocal.otpLastSentAt).getTime())) / 1000
      );
      res.status(429).json({
        message: `Please wait ${retryAfterSeconds}s before requesting another verification code.`,
        retryAfterSeconds,
      });
      return;
    }

    await sendOtpEmail(normalizedEmail, userLocal.name, otp);

    await runStoreTransaction((db) => {
      const user = db.users.find(
        (u) => u.email.trim().toLowerCase() === normalizedEmail
      );
      if (!user) return;
      user.otpHash = otpHash;
      user.otpExpires = otpExpires.toISOString();
      user.otpLastSentAt = otpLastSentAt.toISOString();
      user.otpAttempts = 0;
      user.updatedAt = new Date(now).toISOString();
    });

    res.json({
      message: 'A new 6-digit verification code has been sent to your email.',
      cooldownSeconds: 60,
      expiresInSeconds: 300,
    });
  } catch (err) {
    const error = err as Error & { status?: number; code?: string };
    res.status(error.status || 500).json({
      message: error.message || 'Could not resend OTP.',
      code: error.code,
    });
  }
}

export async function loginUser(req: Request, res: Response): Promise<void> {
  try {
    const { identifier, email, password } = req.body as {
      identifier?: string;
      email?: string;
      password?: string;
    };
    const loginIdentifier = identifier ?? email;
    if (
      typeof loginIdentifier !== 'string' ||
      !loginIdentifier.trim() ||
      typeof password !== 'string' ||
      !password
    ) {
      res.status(400).json({ message: 'Please enter an email or username and password.' });
      return;
    }

    const normalizedIdentifier = loginIdentifier.trim().toLowerCase();

    if (isMongoConnected()) {
      const user = await UserModel.findOne({
        $or: [{ email: normalizedIdentifier }, { username: normalizedIdentifier }],
      })
        .collation({ locale: 'en', strength: 2 })
        .select('+password');
      const passwordMatches = user
        ? await user.comparePassword(password)
        : await bcrypt.compare(password, DUMMY_PASSWORD_HASH);
      if (!user || !passwordMatches) {
        res.status(401).json({ message: 'Invalid email/username or password.' });
        return;
      }
      if (!user.isVerified) {
        res.status(403).json({
          message: 'Please verify your email OTP before logging in.',
          needsVerification: true,
          email: user.email,
        });
        return;
      }

      const token = signAuthToken({
        id: user._id.toString(),
        name: user.name,
        email: user.email,
        role: user.role,
        isVerified: user.isVerified,
      });

      res.json({
        token,
        user: {
          id: user._id.toString(),
          name: user.name,
          username: user.username,
          email: user.email,
          role: user.role,
          isVerified: user.isVerified,
          wishlist: user.wishlist.map((id) => id.toString()),
          shippingAddress: user.shippingAddress,
        },
      });
      return;
    }

    const db = loadStore();
    const user = db.users.find(
      (u) =>
        u.email.trim().toLowerCase() === normalizedIdentifier ||
        u.username?.trim().toLowerCase() === normalizedIdentifier
    );
    const passwordMatches = await bcrypt.compare(
      password,
      user?.password ?? DUMMY_PASSWORD_HASH
    );
    if (!user || !passwordMatches) {
      res.status(401).json({ message: 'Invalid email/username or password.' });
      return;
    }
    if (!user.isVerified) {
      res.status(403).json({
        message: 'Please verify your email OTP before logging in.',
        needsVerification: true,
        email: user.email,
      });
      return;
    }

    const token = signAuthToken({
      id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
      isVerified: user.isVerified,
    });

    res.json({
      token,
      user: {
        id: user._id,
        name: user.name,
        username: user.username,
        email: user.email,
        role: user.role,
        isVerified: user.isVerified,
        wishlist: user.wishlist,
        shippingAddress: user.shippingAddress,
      },
    });
  } catch (err) {
    console.error('[BookHaven Auth] Login failed:', err);
    res.status(500).json({ message: 'Unable to sign in right now. Please try again later.' });
  }
}

export async function getProfile(req: AuthenticatedRequest, res: Response): Promise<void> {
  try {
    if (!req.user) {
      res.status(401).json({ message: 'Not authorized.' });
      return;
    }

    if (isMongoConnected()) {
      const user = await UserModel.findById(req.user.id);
      if (!user) {
        res.status(404).json({ message: 'User not found.' });
        return;
      }
      res.json({
        user: {
          id: user._id.toString(),
          name: user.name,
          username: user.username,
          email: user.email,
          role: user.role,
          isVerified: user.isVerified,
          wishlist: user.wishlist.map((id) => id.toString()),
          shippingAddress: user.shippingAddress,
        },
      });
      return;
    }

    const db = loadStore();
    const user = db.users.find((u) => u._id === req.user!.id);
    if (!user) {
      res.status(404).json({ message: 'User not found.' });
      return;
    }
    res.json({
      user: {
        id: user._id,
        name: user.name,
        username: user.username,
        email: user.email,
        role: user.role,
        isVerified: user.isVerified,
        wishlist: user.wishlist,
        shippingAddress: user.shippingAddress,
      },
    });
  } catch (err) {
    res.status(500).json({ message: (err as Error).message || 'Could not load profile.' });
  }
}

export async function updateProfile(req: AuthenticatedRequest, res: Response): Promise<void> {
  try {
    if (!req.user) {
      res.status(401).json({ message: 'Not authorized.' });
      return;
    }
    const { name, shippingAddress } = req.body as {
      name?: string;
      shippingAddress?: {
        fullName: string;
        phone: string;
        streetAddress: string;
        township: string;
        city: string;
        postalCode: string;
      };
    };

    if (isMongoConnected()) {
      const user = await UserModel.findById(req.user.id);
      if (!user) {
        res.status(404).json({ message: 'User not found.' });
        return;
      }
      if (name && name.trim().length >= 2) user.name = name.trim();
      if (shippingAddress) user.shippingAddress = shippingAddress;
      await user.save();
      res.json({
        user: {
          id: user._id.toString(),
          name: user.name,
          username: user.username,
          email: user.email,
          role: user.role,
          isVerified: user.isVerified,
          wishlist: user.wishlist.map((id) => id.toString()),
          shippingAddress: user.shippingAddress,
        },
      });
      return;
    }

    const updated = await runStoreTransaction((db) => {
      const user = db.users.find((u) => u._id === req.user!.id);
      if (!user) {
        const err = new Error('User not found.') as Error & { status?: number };
        err.status = 404;
        throw err;
      }
      if (name && name.trim().length >= 2) user.name = name.trim();
      if (shippingAddress) user.shippingAddress = shippingAddress;
      user.updatedAt = new Date().toISOString();
      return user;
    });

    res.json({
      user: {
        id: updated._id,
        name: updated.name,
        username: updated.username,
        email: updated.email,
        role: updated.role,
        isVerified: updated.isVerified,
        wishlist: updated.wishlist,
        shippingAddress: updated.shippingAddress,
      },
    });
  } catch (err) {
    const error = err as Error & { status?: number };
    res.status(error.status || 500).json({ message: error.message || 'Profile update failed.' });
  }
}

export async function toggleWishlist(req: AuthenticatedRequest, res: Response): Promise<void> {
  try {
    if (!req.user) {
      res.status(401).json({ message: 'Not authorized.' });
      return;
    }
    const { bookId } = req.params;

    if (isMongoConnected()) {
      const user = await UserModel.findById(req.user.id);
      if (!user) {
        res.status(404).json({ message: 'User not found.' });
        return;
      }
      const exists = user.wishlist.some((id) => id.toString() === bookId);
      if (exists) {
        user.wishlist = user.wishlist.filter((id) => id.toString() !== bookId);
      } else {
        user.wishlist.push(new mongoose.Types.ObjectId(bookId));
      }
      await user.save();
      res.json({ wishlist: user.wishlist.map((id) => id.toString()) });
      return;
    }

    const wishlist = await runStoreTransaction((db) => {
      const user = db.users.find((u) => u._id === req.user!.id);
      if (!user) {
        const err = new Error('User not found.') as Error & { status?: number };
        err.status = 404;
        throw err;
      }
      if (user.wishlist.includes(bookId)) {
        user.wishlist = user.wishlist.filter((id) => id !== bookId);
      } else {
        user.wishlist.push(bookId);
      }
      user.updatedAt = new Date().toISOString();
      return user.wishlist;
    });

    res.json({ wishlist });
  } catch (err) {
    const error = err as Error & { status?: number };
    res.status(error.status || 500).json({ message: error.message || 'Wishlist update failed.' });
  }
}

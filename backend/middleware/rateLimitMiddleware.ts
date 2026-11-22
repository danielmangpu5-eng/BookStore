import { NextFunction, Request, Response } from 'express';

interface RateBucket {
  count: number;
  resetAt: number;
}

export function createRateLimiter(options: {
  windowMs: number;
  maxRequests: number;
  keyPrefix: string;
  message: string;
  keyByIpOnly?: boolean;
}) {
  const buckets = new Map<string, RateBucket>();
  let nextCleanupAt = Date.now() + Math.min(options.windowMs, 60_000);

  return (req: Request, res: Response, next: NextFunction): void => {
    const now = Date.now();
    if (now >= nextCleanupAt) {
      for (const [key, bucket] of buckets) {
        if (bucket.resetAt <= now) buckets.delete(key);
      }
      nextCleanupAt = now + Math.min(options.windowMs, 60_000);
    }

    const clientIp = req.ip || req.socket.remoteAddress || 'unknown';
    const identity = req.body?.identifier ?? req.body?.email;
    const identityPart =
      !options.keyByIpOnly && typeof identity === 'string' ? identity.trim().toLowerCase() : '';
    const key = `${options.keyPrefix}:${clientIp}:${identityPart}`;

    const existing = buckets.get(key);
    if (!existing || existing.resetAt <= now) {
      buckets.set(key, { count: 1, resetAt: now + options.windowMs });
      next();
      return;
    }

    if (existing.count >= options.maxRequests) {
      const retryAfterSeconds = Math.max(1, Math.ceil((existing.resetAt - now) / 1000));
      res.setHeader('Retry-After', String(retryAfterSeconds));
      res.status(429).json({
        message: options.message,
        retryAfterSeconds,
      });
      return;
    }

    existing.count += 1;
    next();
  };
}

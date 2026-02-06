import type { Context, Next } from 'hono';
import type { AppEnv, MoltbotEnv } from '../types';
import { verifyAccessJWT } from './jwt';

/**
 * Options for creating an access middleware
 */
export interface AccessMiddlewareOptions {
  /** Response type: 'json' for API routes, 'html' for UI routes */
  type: 'json' | 'html';
  /** Whether to redirect to login when JWT is missing (only for 'html' type) */
  redirectOnMissing?: boolean;
}

/**
 * Check if running in development mode (skips CF Access auth + device pairing)
 */
export function isDevMode(env: MoltbotEnv): boolean {
  return env.DEV_MODE === 'true';
}

/**
 * Check if running in E2E test mode (skips CF Access auth but keeps device pairing)
 */
export function isE2ETestMode(env: MoltbotEnv): boolean {
  return env.E2E_TEST_MODE === 'true';
}

/**
 * Extract JWT from request headers or cookies
 */
export function extractJWT(c: Context<AppEnv>): string | null {
  const jwtHeader = c.req.header('CF-Access-JWT-Assertion');
  const jwtCookie = c.req.raw.headers.get('Cookie')
    ?.split(';')
    .find(cookie => cookie.trim().startsWith('CF_Authorization='))
    ?.split('=')[1];

  return jwtHeader || jwtCookie || null;
}

/**
 * Create a Cloudflare Access authentication middleware
 * 
 * @param options - Middleware options
 * @returns Hono middleware function
 */
import { basicAuth } from 'hono/basic-auth';

/**
 * Create a Cloudflare Access authentication middleware
 * 
 * @param options - Middleware options
 * @returns Hono middleware function
 */
export function createAccessMiddleware(options: AccessMiddlewareOptions) {
  const { type, redirectOnMissing = false } = options;

  return async (c: Context<AppEnv>, next: Next) => {
    // Skip auth in dev mode or E2E test mode
    if (isDevMode(c.env) || isE2ETestMode(c.env)) {
      c.set('accessUser', { email: 'dev@localhost', name: 'Dev User' });
      return next();
    }

    const teamDomain = c.env.CF_ACCESS_TEAM_DOMAIN;
    const expectedAud = c.env.CF_ACCESS_AUD;

    // 1. Try Cloudflare Access first
    if (teamDomain && expectedAud) {
      // Get JWT
      const jwt = extractJWT(c);

      if (!jwt) {
        if (type === 'html' && redirectOnMissing) {
          return c.redirect(`https://${teamDomain}`, 302);
        }

        if (type === 'json') {
          return c.json({
            error: 'Unauthorized',
            hint: 'Missing Cloudflare Access JWT. Ensure this route is protected by Cloudflare Access.',
          }, 401);
        } else {
          return c.html(`
            <html>
              <body>
                <h1>Unauthorized</h1>
                <p>Missing Cloudflare Access token.</p>
                <a href="https://${teamDomain}">Login</a>
              </body>
            </html>
          `, 401);
        }
      }

      // Verify JWT
      try {
        const payload = await verifyAccessJWT(jwt, teamDomain, expectedAud);
        c.set('accessUser', { email: payload.email, name: payload.name });
        return next();
      } catch (err) {
        console.error('Access JWT verification failed:', err);

        if (type === 'json') {
          return c.json({
            error: 'Unauthorized',
            details: err instanceof Error ? err.message : 'JWT verification failed',
          }, 401);
        } else {
          return c.html(`
            <html>
              <body>
                <h1>Unauthorized</h1>
                <p>Your Cloudflare Access session is invalid or expired.</p>
                <a href="https://${teamDomain}">Login again</a>
              </body>
            </html>
          `, 401);
        }
      }
    }

    // 2. Fallback to Basic Auth
    if (c.env.BASIC_AUTH_USER && c.env.BASIC_AUTH_PASS) {
      const auth = basicAuth({
        username: c.env.BASIC_AUTH_USER,
        password: c.env.BASIC_AUTH_PASS,
      });
      // Set dummy user for Basic Auth
      c.set('accessUser', { email: 'user@basic-auth', name: 'Authorized User' });
      return auth(c, next);
    }

    // 3. No auth configured
    if (type === 'json') {
      return c.json({
        error: 'Authentication not configured',
        hint: 'Set CF_ACCESS_TEAM_DOMAIN/CF_ACCESS_AUD for Zero Trust, or BASIC_AUTH_USER/BASIC_AUTH_PASS for Basic Auth.',
      }, 500);
    } else {
      return c.html(`
        <html>
          <body>
            <h1>Authentication Not Configured</h1>
            <p>Set CF_ACCESS_TEAM_DOMAIN/CF_ACCESS_AUD (Zero Trust) or BASIC_AUTH_USER/BASIC_AUTH_PASS (Basic Auth) environment variables.</p>
          </body>
        </html>
      `, 500);
    }
  };
}

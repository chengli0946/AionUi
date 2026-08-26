import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { PREVIEW_SCOPE_KEY_PREFIX } from '@/renderer/pages/conversation/Preview/context/previewScope';
import { refreshSession } from '@/common/adapter/sessionRefresh';
// M6: CSRF removed with legacy webserver — stub functions for compatibility, re-implement in M7
const withCsrfToken = <T extends Record<string, unknown>>(data: T): T => data;
const hasValidCsrfToken = (): boolean => true;
const clearCookie = (_name: string, _path?: string): void => {};
const CSRF_COOKIE_NAME = 'csrf-token';

type AuthStatus = 'checking' | 'authenticated' | 'unauthenticated';

export interface AuthUser {
  id: string;
  username: string;
}

interface LoginParams {
  username: string;
  password: string;
  remember?: boolean;
}

type LoginErrorCode =
  | 'invalidCredentials'
  | 'tooManyAttempts'
  | 'serverError'
  | 'networkError'
  | 'csrfError'
  | 'unknown';

interface LoginResult {
  success: boolean;
  message?: string;
  code?: LoginErrorCode;
  shouldClearCache?: boolean;
}

interface AuthContextValue {
  ready: boolean;
  user: AuthUser | null;
  status: AuthStatus;
  login: (params: LoginParams) => Promise<LoginResult>;
  logout: () => Promise<void>;
  refresh: () => Promise<void>;
  clearAuthCache: () => void;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

const AUTH_USER_ENDPOINT = '/api/auth/user';

const isDesktopRuntime = typeof window !== 'undefined' && Boolean(window.electronAPI);

// Clear expired auth cache including cookies and localStorage
// 清除过期的认证缓存，包括 Cookie 和 localStorage
function clearAuthCache(): void {
  if (typeof window === 'undefined') return;

  try {
    // Clear CSRF cookie
    clearCookie(CSRF_COOKIE_NAME);
    clearCookie(CSRF_COOKIE_NAME, '/');

    // Clear localStorage auth-related items, plus per-user UI state that must not
    // leak across accounts. Preview scopes are keyed by project id and hold file
    // content, so leaving them behind would show the next user the previous one's
    // open tabs — and nothing else ever cleaned them up.
    const keysToRemove: string[] = [];
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (
        key &&
        (key.includes('auth') ||
          key.includes('csrf') ||
          key.includes('token') ||
          key.startsWith(PREVIEW_SCOPE_KEY_PREFIX))
      ) {
        keysToRemove.push(key);
      }
    }
    keysToRemove.forEach((key) => localStorage.removeItem(key));
  } catch (error) {
    console.error('Failed to clear auth cache:', error);
  }
}

async function fetchCurrentUser(signal?: AbortSignal): Promise<AuthUser | null> {
  // iOS Safari fix: bound the auth check so the UI can never sit on the
  // infinite "checking"/AppLoader state when the request hangs (e.g. the
  // per-host connection pool is saturated). After 8s we abort and fall back
  // to the login form instead of a spinner forever.
  const controller = new AbortController();
  const timeoutId = window.setTimeout(() => controller.abort(), 8000);
  const onOuterAbort = () => controller.abort();
  signal?.addEventListener('abort', onOuterAbort);

  try {
    let response = await fetch(AUTH_USER_ENDPOINT, {
      method: 'GET',
      credentials: 'include',
      signal: controller.signal,
    });

    // The access cookie may have expired — attempt one silent session refresh
    // and re-check before concluding the user is unauthenticated. Without this
    // the status poll would kick a refreshable session to /login (#4124).
    // refreshSession() single-flights with the httpBridge refresh path.
    if (response.status === 401) {
      const refreshed = await refreshSession();
      if (refreshed) {
        response = await fetch(AUTH_USER_ENDPOINT, {
          method: 'GET',
          credentials: 'include',
          signal,
        });
      }
    }

    if (!response.ok) {
      return null;
    }

    const data = (await response.json()) as {
      success: boolean;
      user?: AuthUser;
    };
    if (data.success && data.user) {
      return data.user;
    }
  } catch (error) {
    if ((error as Error).name === 'AbortError') {
      return null;
    }
    console.error('Failed to fetch current user:', error);
  } finally {
    window.clearTimeout(timeoutId);
    signal?.removeEventListener('abort', onOuterAbort);
  }

  return null;
}

export const AuthProvider: React.FC<React.PropsWithChildren> = ({ children }) => {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [status, setStatus] = useState<AuthStatus>('checking');
  const [ready, setReady] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  const refresh = useCallback(async () => {
    if (isDesktopRuntime) {
      setStatus('authenticated');
      setUser(null);
      setReady(true);
      return;
    }

    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;
    setStatus('checking');

    const currentUser = await fetchCurrentUser(controller.signal);
    if (currentUser) {
      setUser(currentUser);
      setStatus('authenticated');
    } else {
      setUser(null);
      setStatus('unauthenticated');
    }
    setReady(true);
  }, []);

  useEffect(() => {
    void refresh();
    return () => {
      abortRef.current?.abort();
    };
  }, [refresh]);

  const login = useCallback(async ({ username, password, remember }: LoginParams): Promise<LoginResult> => {
    try {
      if (isDesktopRuntime) {
        setReady(true);
        return { success: true };
      }

      // Check CSRF token availability before login
      // If token is missing, clear cache and inform user
      const csrfTokenValid = hasValidCsrfToken();
      if (!csrfTokenValid) {
        console.warn('CSRF token missing or invalid, clearing cache');
        clearAuthCache();
        // Allow login to proceed anyway - server will set new token
      }

      // P1 安全修复：登录请求需要 CSRF Token / P1 Security fix: Login needs CSRF token
      // Backend route is /login; web-host's static-server explicitly proxies it.
      // iOS Safari fix: the request may reach the server while the response is
      // lost on the return path (lossy VPN/campus network), leaving fetch()
      // hanging. Retry a few times with a short timeout so a blip doesn't
      // dead-end the user; each attempt that reaches the server shows up in
      // the backend log, and the first response that gets through wins.
      const MAX_LOGIN_ATTEMPTS = 3;
      const LOGIN_ATTEMPT_TIMEOUT_MS = 8000;
      let response: Response | undefined;
      let lastLoginError: unknown = null;
      for (let attempt = 0; attempt < MAX_LOGIN_ATTEMPTS; attempt++) {
        const loginController = new AbortController();
        const loginTimeoutId = window.setTimeout(() => loginController.abort(), LOGIN_ATTEMPT_TIMEOUT_MS);
        try {
          response = await fetch('/login', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            credentials: 'include',
            signal: loginController.signal,
            body: JSON.stringify(withCsrfToken({ username, password, remember })),
          });
          break;
        } catch (error) {
          lastLoginError = error;
          window.clearTimeout(loginTimeoutId);
          if (attempt === MAX_LOGIN_ATTEMPTS - 1) {
            throw error;
          }
          // Brief pause before retrying so a recovering network can settle.
          await new Promise((resolve) => window.setTimeout(resolve, 600));
        }
      }
      if (!response) {
        throw lastLoginError ?? new Error('Login request failed');
      }

      const data = (await response.json()) as {
        success: boolean;
        message?: string;
        user?: AuthUser;
      };

      if (!response.ok || !data.success || !data.user) {
        let code: LoginErrorCode = 'unknown';
        let message = data?.message ?? 'Login failed';
        let shouldClearCache = false;

        if (response.status === 401) {
          code = 'invalidCredentials';
        } else if (response.status === 403) {
          // CSRF validation failed - clear cache
          code = 'csrfError';
          message = 'Security token expired. Please try again.';
          shouldClearCache = true;
        } else if (response.status === 429) {
          code = 'tooManyAttempts';
        } else if (response.status >= 500) {
          code = 'serverError';
        } else if (!csrfTokenValid) {
          // If we knew CSRF was invalid and login failed, suggest cache clear
          code = 'csrfError';
          message = 'Login failed due to cached data. Please clear your browser cache and try again.';
          shouldClearCache = true;
        }

        // Clear cache on CSRF-related errors
        if (shouldClearCache) {
          clearAuthCache();
        }

        return {
          success: false,
          message,
          code,
          shouldClearCache,
        };
      }

      setUser(data.user);
      setStatus('authenticated');
      setReady(true);

      // Re-enable WebSocket reconnection after successful login (WebUI mode only)
      if (typeof window !== 'undefined' && (window as any).__websocketReconnect) {
        (window as any).__websocketReconnect();
      }

      return { success: true };
    } catch (error) {
      console.error('Login request failed:', error);

      // Check if error is related to CSRF token parsing
      const errorMessage = (error as Error).message;
      if (errorMessage?.includes('parse') || errorMessage?.includes('csrf') || errorMessage?.includes('cookie')) {
        // CSRF or cookie parsing error - clear cache
        clearAuthCache();
        return {
          success: false,
          message: 'Login failed due to cached data. Please clear your browser cache and try again.',
          code: 'csrfError',
          shouldClearCache: true,
        };
      }

      return {
        success: false,
        message: 'Network error. Please try again.',
        code: 'networkError',
      };
    }
  }, []);

  const logout = useCallback(async () => {
    if (isDesktopRuntime) {
      setUser(null);
      setStatus('authenticated');
      setReady(true);
      return;
    }

    // iOS Safari fix: optimistic logout. The network path from iOS to the
    // server is lossy in both directions — the POST /logout may reach the
    // server (200) while the response never makes it back to the client, so
    // `await fetch(...)` hangs until its timeout and the UI only transitions
    // seconds later. Clear local auth state IMMEDIATELY (flip status, purge
    // cache) and fire the server-side invalidation in the background without
    // blocking the UI on it.
    setUser(null);
    setStatus('unauthenticated');
    clearAuthCache();

    const logoutController = new AbortController();
    const logoutTimeoutId = window.setTimeout(() => logoutController.abort(), 4000);
    fetch('/logout', {
      method: 'POST',
      // Logout also needs CSRF token / 登出同样需要 CSRF Token
      headers: {
        'Content-Type': 'application/json',
      },
      credentials: 'include',
      signal: logoutController.signal,
      body: JSON.stringify(withCsrfToken({})),
    })
      .catch((error) => {
        console.error('Logout request failed:', error);
      })
      .finally(() => {
        window.clearTimeout(logoutTimeoutId);
      });
  }, []);

  const value = useMemo<AuthContextValue>(
    () => ({
      ready,
      user,
      status,
      login,
      logout,
      refresh,
      clearAuthCache,
    }),
    [login, logout, ready, refresh, status, user]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

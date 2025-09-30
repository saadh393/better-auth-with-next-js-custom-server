# Better Auth with Next.js and an External Backend

This guide documents the end-to-end setup for using [Better Auth](https://better-auth.dev/) inside a **Next.js 15** application that delegates authentication to a **custom Node.js + MongoDB** backend. It covers server-side proxy routes, session refresh logic, device fingerprinting, and UI consumption for both client and server components.

Use this document as a reference when you need to wire a Next.js front end to an existing auth service without relying on the Better Auth server packages.

---

## 1. Prerequisites

- **Next.js 15 (App Router)** with React 19.
- Existing **Node.js backend** exposing endpoints for `login`, `register`, `refresh-token`, `logout`, and optional multi-factor `verify-otp`.
- Backend returns payloads shaped like:

  ```json
  {
    "user": { "name": "...", "email": "...", "id": "..." },
    "tokens": { "token": "ACCESS_JWT", "expires": "ISO", "expiresIn": 18000 }
  }
  ```

- A refresh token cookie (`__refresh_token`) is issued by the backend on login/refresh.
- Device fingerprint is required by the backend when exchanging refresh tokens.

---

## 2. Architecture Overview

```
Browser ↔ Next.js App Router
         ↕   ▲
         ↓   │
    /api/auth/* (Next.js edge/server routes)
         │
         ↓
 Custom Node.js Auth API (/auth/login, /auth/logout, ...)
```

Key goals:

1. **Proxy all auth traffic through Next.js.**
2. **Forward backend cookies untouched** while attaching the device fingerprint cookie controlled by the frontend.
3. **Expose a Better Auth client store** inside React so components can read sessions.
4. **Refresh user on SSR/ISR/SSG** without exposing backend secrets in the browser.

---

## 3. Shared Utilities

### 3.1 Backend Caller (`lib/auth/backend.js`)

Creates helper functions to resolve the backend base URL, proxy requests, and append cookies from the backend response to the Next.js response.

```js
// lib/auth/backend.js
export async function callAuthBackend(path, options = {}) {
  const url = buildAuthUrl(path);
  const response = await fetch(url, {
    method: options.method ?? "GET",
    headers: { ...options.headers },
    ...("body" in options ? { body: JSON.stringify(options.body) } : {}),
    credentials: "include",
    cache: "no-store",
  });

  let data = null;
  const text = await response.text();
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
  }

  return { response, data };
}
```

> **Why:** Keeps auth route handlers lean and ensures every proxy request forwards cookies and JSON payloads consistently.

### 3.2 Device Fingerprint (`lib/auth/device.js`)

Ensures every auth call includes an identifier that the backend expects to bind refresh tokens to devices.

```js
// lib/auth/device.js
export function resolveDeviceFingerprint(cookieStore, userAgent = "") {
  const existing = cookieStore?.get?.(FINGERPRINT_COOKIE)?.value;
  const fingerprint = existing || randomUUID();

  return {
    id: fingerprint,
    payload: {
      fingerprint,
      os: detectOS(userAgent),
      browser: detectBrowser(userAgent),
    },
  };
}

export function setDeviceFingerprintCookie(response, fingerprint) {
  const cookie = serializeCookie(FINGERPRINT_COOKIE, fingerprint, {
    path: "/",
    httpOnly: false,
    sameSite: "Lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 60 * 60 * 24 * 365,
  });

  response.headers.append("set-cookie", cookie);
}
```

> **Why:** The backend requires `{ fingerprint, os, browser }`. We memoise it in a cookie so user sessions survive reloads and SSR.

---

## 4. Next.js Auth API Routes

Each authentication flow is proxied through `app/api/auth/*` routes. These run on the server, forward incoming cookies, attach device fingerprint payloads, and preserve backend `Set-Cookie` headers.

### 4.1 Login (`app/api/auth/login/route.js`)

```js
export async function POST(request) {
  const body = await request.json().catch(() => ({}));
  const headersStore = headers();
  const cookieStore = cookies();
  const fingerprint = resolveDeviceFingerprint(cookieStore, headersStore.get("user-agent") || "");

  const { response: backendResponse, data } = await callAuthBackend("/login", {
    method: "POST",
    headers: forwardCookies(headersStore),
    body: {
      ...body,
      fingerprint: {
        ...(body.fingerprint ?? {}),
        ...fingerprint.payload,
      },
    },
  });

  const nextResponse = NextResponse.json(data ?? null, {
    status: backendResponse.status,
  });

  appendBackendCookies(nextResponse, backendResponse);
  setDeviceFingerprintCookie(nextResponse, fingerprint.id);
  return nextResponse;
}
```

Highlights:
- Merges any payload-supplied fingerprint with our computed one.
- Propagates backend cookies (access/refresh tokens) to the browser.
- Adds/refreshes our `device_fingerprint` cookie.

### 4.2 Register & OTP

Both follow the same pattern as login—call the backend with `{ ...body }`, append cookies on success, and store the device fingerprint.

- `app/api/auth/register/route.js`
- `app/api/auth/verify-otp/route.js`

### 4.3 Refresh Session (`app/api/auth/get-session/route.js`)

Invoked automatically by Better Auth when the client needs session data.

```js
export async function GET() {
  const cookieStore = cookies();
  const hasRefresh = cookieStore.get("__refresh_token");
  const headersStore = headers();
  const fingerprint = resolveDeviceFingerprint(cookieStore, headersStore.get("user-agent") || "");

  if (!hasRefresh) {
    const res = NextResponse.json(null, { status: 200 });
    setDeviceFingerprintCookie(res, fingerprint.id);
    return res;
  }

  const { response, data } = await callAuthBackend("/refresh-token", {
    method: "POST",
    headers: forwardCookies(headersStore),
    body: { fingerprint: fingerprint.payload },
  });

  if (response.ok) {
    const res = NextResponse.json(data ?? null, { status: 200 });
    appendBackendCookies(res, response);
    setDeviceFingerprintCookie(res, fingerprint.id);
    return res;
  }

  // Refresh token expired → clear and return null
  const res = NextResponse.json(null, { status: 200 });
  clearRefreshCookie(res);
  setDeviceFingerprintCookie(res, fingerprint.id);
  return res;
}
```

### 4.4 Logout (`app/api/auth/logout/route.js`)

```js
const isNoContent = backendResponse.status === 204;
const status = isNoContent ? 200 : backendResponse.status;

const nextResponse = NextResponse.json(
  isNoContent ? { success: true } : responseBody,
  { status }
);
```

- Always return a JSON payload (required by `NextResponse.json`).
- Clear the refresh cookie client-side, even if the backend has already removed it.

---

## 5. Better Auth Client Setup

Better Auth’s React client (`better-auth/react`) provides a Nanostore-driven session that works seamlessly with App Router components.

```js
// lib/auth.js
import { createAuthClient } from "better-auth/react";
import { nextCookies } from "better-auth/next-js";

const authClient = createAuthClient({
  basePath: "/api/auth",
  plugins: [backendAuthPlugin, nextCookies()],
  fetchOptions: { cache: "no-store" },
});

export const auth = {
  login: (payload) => authClient.login(payload),
  register: (payload) => authClient.register(payload),
  verifyOtp: (payload) => authClient.verifyOtp(payload),
  logout: () => authClient.logout(),
  refresh: (query) => authClient.refreshSession(query),
  getSession: () => (authClient.session.get?.()?.data ?? null),
  useSession: () => authClient.useSession(),
};
```

### 5.1 Custom Plugin (`backendAuthPlugin`)

Better Auth expects to call `/sign-in`/`/sign-up` endpoints by default. Because we proxy to `/api/auth/*`, we create a custom plugin that wraps `$fetch` calls and normalises responses.

```js
const backendAuthPlugin = {
  id: "backend-auth-client",
  getActions: ($fetch, $store) => ({
    async login(body) {
      const result = await $fetch("/login", { method: "POST", body });
      if (result?.error) throw new Error(result.error.message || "Login failed");
      const normalized = normalizeAuthPayload(result?.data, body?.email);
      if (!normalized.otpRequired) $store.notify("$sessionSignal");
      return normalized;
    },
    // register, verifyOtp, logout, refreshSession ...
  }),
};
```

> **Tip:** The plugin calls `$store.notify("$sessionSignal")` to trigger Better Auth’s internal session refetch when login/logout succeed.

### 5.2 Session Hooks

For client components, consume session state using `auth.useSession()`:

```jsx
const session = auth.useSession();
const user = session?.data?.user;

return user ? <Dashboard /> : <LoginLink />;
```

Because `useSession` relies on the Nanostore, React components update immediately after login/logout.

---

## 6. UI Integration Examples

### 6.1 Login Form (`app/auth/components/login-form.jsx`)

```jsx
async function onSubmit(values) {
  try {
    const result = await auth.login(values);

    if (result?.otpRequired) {
      router.push(`/auth/otp?email=${encodeURIComponent(result.email ?? values.email)}`);
      return;
    }

    toast.success("Login successful!");
    router.push("/");
  } catch (error) {
    toast.error(error?.message || "Login failed");
  }
}
```

### 6.2 Header Menu (`components/header.jsx`)

```jsx
const session = auth.useSession();
const user = session?.data?.user ?? null;

return user ? (
  <Button onClick={auth.logout}>Logout</Button>
) : (
  <Link href="/auth/login">Login</Link>
);
```

### 6.3 Payment Page Guard (`app/payment/[slug]/page.jsx`)

```jsx
const session = auth.useSession();
const user = session?.data?.user;
// Use `user` to gate payment flow or show purchase information.
```

---

## 7. Server-Side Access (SSR/ISR/SSG)

Use `lib/auth/server.js` to read the current user during server rendering without hitting the client store:

```js
// lib/auth/server.js
export async function getServerSession({ skipNoStore = false } = {}) {
  if (!skipNoStore) noStore();

  const headerStore = headers();
  const cookieStore = cookies();
  const fingerprint = resolveDeviceFingerprint(cookieStore, headerStore.get("user-agent") || "");

  const hasRefresh = cookieStore.get("__refresh_token");
  if (!hasRefresh) return null;

  const { response, data } = await callAuthBackend("/refresh-token", {
    method: "POST",
    headers: forwardCookies(headerStore),
    body: { fingerprint: fingerprint.payload },
  });

  if (!response.ok) return null;
  return normalizeSessionResponse(data);
}
```

### Usage Example (Server Component)

```jsx
import { getServerSession } from "@/lib/auth/server";

export default async function DashboardPage() {
  const session = await getServerSession();

  if (!session?.user) {
    redirect("/auth/login");
  }

  return <DashboardShell user={session.user} />;
}
```

---

## 8. Testing Checklist

1. **Login Flow**
   - POST `/api/auth/login` with valid credentials ⇒ returns user/tokens.
   - Browser receives both `__refresh_token` (httpOnly) and `device_fingerprint` cookies.

2. **Session Refresh**
   - GET `/api/auth/get-session` returns the same payload when refresh cookie is present.
   - When refresh token is manually cleared, route responds with `null` and clears cookies.

3. **Logout**
   - POST `/api/auth/logout` returns `{ success: true }` and clears cookies.

4. **OTP Flow** (if enabled)
   - POST `/api/auth/login` for a user that requires OTP ⇒ `otpRequired: true`.
   - POST `/api/auth/verify-otp` with code ⇒ session established.

5. **SSR Guard**
   - Call `getServerSession()` during a server render; ensure it fetches the backend refresh endpoint once and returns user data.

---

## 9. Troubleshooting

| Issue | Likely Cause | Fix |
| --- | --- | --- |
| `/api/auth/get-session` returns `null` even after login | Refresh cookie not preserved | Ensure `appendBackendCookies(nextResponse, backendResponse)` runs **before** writing custom cookies, and `setDeviceFingerprintCookie` uses `response.headers.append` (not `response.cookies.set`). |
| `Response constructor: Invalid response status code 204` | Calling `NextResponse.json` with a `204` status | Coerce `204 → 200` and include a JSON payload such as `{ success: true }`. |
| Session updates not reflected in UI | Components read stale cache | Use `auth.useSession()` in client components or call `auth.refresh()` after mutations that might change the session. |
| Better Auth fetch hits wrong endpoint | Missing `basePath` | Ensure `createAuthClient({ basePath: "/api/auth" })` and custom plugin use the same paths. |

---

## 10. Extending the Integration

- **Role-Based UI**: Use `session.data.user.roles` to gate routes.
- **Server Actions**: Pull `getServerAccessToken()` to inject bearer tokens into backend calls within server actions.
- **Error Telemetry**: Wrap `callAuthBackend` with logging to Sentry or Datadog for easier debugging.
- **Multi-Workspace Support**: If serving multiple tenants, namespace cookies via environment-specific prefixes in `setDeviceFingerprintCookie` and backend `set-cookie` configuration.

---

## 11. References

- Better Auth Docs: <https://better-auth.dev/>
- Next.js App Router Docs: <https://nextjs.org/docs/app>
- Current project sources:
  - `lib/auth.js`
  - `lib/auth/backend.js`
  - `lib/auth/device.js`
  - `lib/auth/server.js`
  - `app/api/auth/*`
  - `components/header.jsx`
  - `app/auth/components/*`

By following the structure above, you can integrate Better Auth into any Next.js application while delegating actual credential verification and token issuance to an existing backend stack.

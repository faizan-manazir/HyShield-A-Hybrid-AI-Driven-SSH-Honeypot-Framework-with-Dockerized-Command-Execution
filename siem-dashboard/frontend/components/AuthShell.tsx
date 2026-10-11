"use client";

import { useEffect, useState } from "react";
import { usePathname, useRouter } from "next/navigation";
import Sidebar from "@/components/Sidebar";
import { API_BASE_URL } from "@/lib/api";

const TOKEN_KEY = "hyshield_siem_token";
const EXPIRY_KEY = TOKEN_KEY + "_expires_at";

export default function AuthShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const [ready, setReady] = useState(false);
  const isLogin = pathname === "/login";

  // Install the API fetch wrapper once. Re-installing it on every route change
  // briefly restores native fetch, allowing child effects to issue unauthenticated
  // requests while navigating from login to the dashboard.
  useEffect(() => {
    const originalFetch = window.fetch.bind(window);
    window.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
      const rawUrl = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      let requestUrl: URL;
      let apiUrl: URL;
      try {
        requestUrl = new URL(rawUrl, window.location.href);
        apiUrl = new URL(API_BASE_URL, window.location.href);
      } catch {
        return originalFetch(input, init);
      }

      // Only attach credentials to the configured API origin, never a lookalike host.
      if (
        requestUrl.origin !== apiUrl.origin ||
        !requestUrl.pathname.startsWith("/api/") ||
        requestUrl.pathname === "/api/auth/login"
      ) {
        return originalFetch(input, init);
      }

      const token = window.sessionStorage.getItem(TOKEN_KEY);
      const expiresAt = Number(window.sessionStorage.getItem(EXPIRY_KEY) || 0);
      if (!token || !expiresAt || Date.now() >= expiresAt) {
        window.sessionStorage.removeItem(TOKEN_KEY);
        window.sessionStorage.removeItem(EXPIRY_KEY);
        if (window.location.pathname !== "/login") router.replace("/login");
        return new Response(JSON.stringify({ error: "Authentication required" }), {
          status: 401,
          headers: { "Content-Type": "application/json" },
        });
      }

      const headers = new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined));
      headers.set("Authorization", `Bearer ${token}`);
      const response = await originalFetch(input, { ...init, headers });

      if (response.status === 401 && window.location.pathname !== "/login") {
        window.sessionStorage.removeItem(TOKEN_KEY);
        window.sessionStorage.removeItem(EXPIRY_KEY);
        router.replace("/login");
      }
      return response;
    };

    return () => {
      // Restore the browser's original fetch when the shell unmounts.
      window.fetch = originalFetch;
    };
  }, [router]);

  // Route/session validation is separate from the stable fetch wrapper, so
  // changing routes does not create a window where API requests lack auth.
  useEffect(() => {
    const token = window.sessionStorage.getItem(TOKEN_KEY);
    const expiresAt = Number(window.sessionStorage.getItem(EXPIRY_KEY) || 0);
    const validSession = Boolean(token && expiresAt && Date.now() < expiresAt);
    const expiryTimer = validSession
      ? window.setTimeout(() => {
          window.sessionStorage.removeItem(TOKEN_KEY);
          window.sessionStorage.removeItem(EXPIRY_KEY);
          router.replace("/login");
        }, Math.max(0, expiresAt - Date.now()))
      : undefined;

    if (!validSession) {
      window.sessionStorage.removeItem(TOKEN_KEY);
      window.sessionStorage.removeItem(EXPIRY_KEY);
    }
    if (!isLogin && !validSession) {
      router.replace("/login");
    } else if (isLogin && validSession) {
      router.replace("/");
    }
    setReady(true);

    return () => {
      if (expiryTimer !== undefined) window.clearTimeout(expiryTimer);
    };
  }, [isLogin, router]);

  if (!ready) return <div className="p-8 text-gray-400">Loading secure session…</div>;
  if (!isLogin && typeof window !== "undefined") {
    const token = window.sessionStorage.getItem(TOKEN_KEY);
    const expiresAt = Number(window.sessionStorage.getItem(EXPIRY_KEY) || 0);
    if (!token || !expiresAt || Date.now() >= expiresAt) {
      return <div className="p-8 text-gray-400">Redirecting to sign in…</div>;
    }
  }

  return (
    <div className="bg-[#050508] text-gray-100 flex min-h-screen font-sans">
      {!isLogin && <Sidebar onLogout={() => {
        window.sessionStorage.removeItem(TOKEN_KEY);
        window.sessionStorage.removeItem(EXPIRY_KEY);
        router.replace("/login");
      }} />}
      <main className="flex-1 overflow-x-hidden overflow-y-auto bg-[#050508]">
        {children}
      </main>
    </div>
  );
}

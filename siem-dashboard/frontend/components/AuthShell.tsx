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

  useEffect(() => {
    const originalFetch = window.fetch.bind(window);
    window.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      if (!url.startsWith(API_BASE_URL) || url.startsWith(`${API_BASE_URL}/api/auth/login`)) {
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
      if (token) headers.set("Authorization", `Bearer ${token}`);
      const response = await originalFetch(input, { ...init, headers });

      if (response.status === 401 && window.location.pathname !== "/login") {
        window.sessionStorage.removeItem(TOKEN_KEY);
        window.sessionStorage.removeItem(EXPIRY_KEY);
        router.replace("/login");
      }
      return response;
    };

    const token = window.sessionStorage.getItem(TOKEN_KEY);
    const expiresAt = Number(window.sessionStorage.getItem(EXPIRY_KEY) || 0);
    const validSession = Boolean(token && expiresAt && Date.now() < expiresAt);
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

    return () => { window.fetch = originalFetch; };
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

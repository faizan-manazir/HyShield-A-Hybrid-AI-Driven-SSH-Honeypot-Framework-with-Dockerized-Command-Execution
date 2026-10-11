"use client";

import { FormEvent, useState } from "react";
import { useRouter } from "next/navigation";
import { ShieldCheck } from "lucide-react";
import { API_BASE_URL } from "@/lib/api";

const TOKEN_KEY = "hyshield_siem_token";

export default function LoginPage() {
  const router = useRouter();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setBusy(true);
    try {
      const response = await fetch(`${API_BASE_URL}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok || typeof payload.access_token !== "string" || !Number.isFinite(payload.expires_in)) {
        setError("Sign-in failed. Check your credentials and try again.");
        return;
      }
      window.sessionStorage.setItem(TOKEN_KEY, payload.access_token);
      window.sessionStorage.setItem(TOKEN_KEY + "_expires_at", String(Date.now() + payload.expires_in * 1000));
      router.replace("/");
    } catch {
      setError("Unable to reach the SIEM API. Check that the backend is running.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center px-6 py-12 bg-[#050508]">
      <div className="w-full max-w-md rounded-2xl border border-white/10 bg-[#111116] p-8 shadow-2xl">
        <div className="flex items-center gap-3 mb-8">
          <div className="w-11 h-11 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center">
            <ShieldCheck className="w-6 h-6 text-cyan-400" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-widest text-white">HYSHIELD</h1>
            <p className="text-xs uppercase tracking-widest text-cyan-500">Secure SIEM sign-in</p>
          </div>
        </div>

        <h2 className="text-lg font-semibold text-white">Sign in to your dashboard</h2>
        <p className="mt-2 mb-6 text-sm text-gray-400">Use the administrator credentials configured for the SIEM API.</p>

        <form onSubmit={handleSubmit} className="space-y-5">
          <div>
            <label htmlFor="username" className="block text-sm text-gray-300 mb-2">Username</label>
            <input id="username" name="username" autoComplete="username" required value={username}
              onChange={event => setUsername(event.target.value)}
              className="w-full rounded-lg border border-white/10 bg-black/30 px-4 py-3 text-white outline-none focus:border-cyan-500"
            />
          </div>
          <div>
            <label htmlFor="password" className="block text-sm text-gray-300 mb-2">Password</label>
            <input id="password" name="password" type="password" autoComplete="current-password" required value={password}
              onChange={event => setPassword(event.target.value)}
              className="w-full rounded-lg border border-white/10 bg-black/30 px-4 py-3 text-white outline-none focus:border-cyan-500"
            />
          </div>
          {error && <p role="alert" className="rounded-lg border border-rose-500/20 bg-rose-500/10 px-3 py-2 text-sm text-rose-300">{error}</p>}
          <button type="submit" disabled={busy}
            className="w-full rounded-lg bg-cyan-600 px-4 py-3 font-semibold text-white transition hover:bg-cyan-500 disabled:cursor-not-allowed disabled:opacity-60">
            {busy ? "Signing in…" : "Sign in"}
          </button>
        </form>
        <p className="mt-6 text-xs leading-relaxed text-gray-500">
          Session tokens are held in this browser tab and cleared when the session ends. Keep the API private and use HTTPS for any remote access.
        </p>
      </div>
    </div>
  );
}

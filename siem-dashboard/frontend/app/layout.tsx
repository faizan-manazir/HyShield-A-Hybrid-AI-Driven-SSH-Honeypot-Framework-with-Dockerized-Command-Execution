import type { Metadata } from "next";
import "./globals.css";
import AuthShell from "@/components/AuthShell";

export const metadata: Metadata = {
  title: "HyShield SIEM",
  description: "HyShield Hybrid AI-Driven SSH Honeypot Framework SIEM",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body>
        <AuthShell>{children}</AuthShell>
      </body>
    </html>
  );
}

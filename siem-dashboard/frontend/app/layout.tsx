import type { Metadata } from "next";
import "./globals.css";
import Sidebar from "@/components/Sidebar";

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
      <body className="bg-[#050508] text-gray-100 flex min-h-screen font-sans">
        <Sidebar />
        <main className="flex-1 overflow-x-hidden overflow-y-auto bg-[#050508]">
          {children}
        </main>
      </body>
    </html>
  );
}

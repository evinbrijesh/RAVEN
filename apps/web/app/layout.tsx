import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";

export const metadata: Metadata = {
  title: "RAVEN — Security Regression for LLM Apps",
  description:
    "Bounded, human-supervised security regression scans for the ShopHelper demo bot.",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body className="min-h-screen">
        <header className="border-b border-zinc-800 bg-zinc-900/60">
          <div className="mx-auto flex max-w-6xl items-center justify-between px-4 py-3">
            <Link href="/" className="flex items-center gap-2 font-semibold">
              <span aria-hidden className="text-lg">
                🐦‍⬛
              </span>
              <span>RAVEN</span>
              <span className="rounded bg-zinc-800 px-1.5 py-0.5 text-xs font-normal text-zinc-400">
                MVP
              </span>
            </Link>
            <nav className="flex items-center gap-4 text-sm text-zinc-400">
              <Link href="/" className="hover:text-zinc-100">
                Scans
              </Link>
              <Link
                href="/scans/new"
                className="rounded-md bg-indigo-600 px-3 py-1.5 font-medium text-white hover:bg-indigo-500"
              >
                New scan
              </Link>
            </nav>
          </div>
        </header>
        <main className="mx-auto max-w-6xl px-4 py-8">{children}</main>
        <footer className="mx-auto max-w-6xl px-4 pb-8 text-xs text-zinc-500">
          Bounded, human-supervised security regression. A clean result is not a
          security guarantee.
        </footer>
      </body>
    </html>
  );
}

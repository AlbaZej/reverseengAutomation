"use client";

import { useEffect, useState } from "react";
import { isLoggedIn, logout } from "@/lib/api";
import { useRouter } from "next/navigation";

export function Nav() {
  const router = useRouter();
  const [loggedIn, setLoggedIn] = useState(false);

  useEffect(() => {
    setLoggedIn(isLoggedIn());
  }, []);

  return (
    <nav className="border-b border-[var(--border)] px-6 py-4">
      <div className="max-w-7xl mx-auto flex items-center justify-between">
        <a href="/" className="text-xl font-bold tracking-wider">
          <span className="text-[var(--accent-blue)]">DESHIFRO</span>
        </a>
        <div className="flex gap-6 text-sm text-[var(--text-secondary)] items-center">
          <a href="/" className="hover:text-[var(--text-primary)] transition">
            Upload
          </a>
          {loggedIn ? (
            <>
              <a
                href="/dashboard"
                className="hover:text-[var(--text-primary)] transition"
              >
                Dashboard
              </a>
              <a
                href="/samples"
                className="hover:text-[var(--text-primary)] transition"
              >
                Samples
              </a>
              <a
                href="/settings"
                className="hover:text-[var(--text-primary)] transition"
              >
                Settings
              </a>
            </>
          ) : (
            <>
              <a
                href="/login"
                className="hover:text-[var(--text-primary)] transition"
              >
                Sign in
              </a>
              <a
                href="/register"
                className="px-3 py-1 bg-[var(--accent-blue)] text-white rounded-md hover:opacity-90 transition"
              >
                Register
              </a>
            </>
          )}
        </div>
      </div>
    </nav>
  );
}

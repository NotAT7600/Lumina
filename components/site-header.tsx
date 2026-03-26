"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

export function SiteHeader() {
  const pathname = usePathname();

  if (pathname === "/") {
    return null;
  }

  return (
    <header
      style={{
        position: "sticky",
        top: 0,
        zIndex: 50,
        display: "flex",
        alignItems: "center",
        height: "56px",
        padding: "0 24px",
        borderBottom: "1px solid rgba(255,255,255,0.07)",
        background: "rgba(8,8,16,0.88)",
        backdropFilter: "blur(16px)",
        WebkitBackdropFilter: "blur(16px)",
      }}
    >
      <div className="page-shell" style={{ width: "100%" }}>
        <div className="page-container">
          <Link
            href="/"
            style={{
              fontFamily: "var(--font-outfit, sans-serif)",
              fontSize: "22px",
              fontWeight: 300,
              letterSpacing: "-0.03em",
              background: "linear-gradient(120deg, #ffffff 0%, #e2e8f0 60%, #94a3b8 100%)",
              WebkitBackgroundClip: "text",
              WebkitTextFillColor: "transparent",
              backgroundClip: "text",
              textDecoration: "none",
              transition: "opacity 0.15s",
            }}
          >
            Lumina
          </Link>
        </div>
      </div>
    </header>
  );
}

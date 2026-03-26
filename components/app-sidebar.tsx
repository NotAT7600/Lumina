"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Shield, FileText, Terminal, Settings } from "lucide-react";

const NAV = [
  { href: "/", icon: Shield, label: "New Scan" },
  { href: "/reports", icon: FileText, label: "Reports" },
  { href: "/scans", icon: Terminal, label: "Scans" },
];

export function AppSidebar() {
  const pathname = usePathname();

  return (
    <aside className="app-sidebar">
      <div className="sidebar-logo">
        <Link href="/" title="Lumina">
          <img
            src="/image.png"
            alt="Lumina"
            width={28}
            height={28}
            className="object-contain opacity-90"
          />
        </Link>
      </div>

      <nav className="sidebar-nav">
        {NAV.map(({ href, icon: Icon, label }) => (
          <Link
            key={href}
            href={href}
            title={label}
            className={`sidebar-item${pathname === href ? " sidebar-item--active" : ""}`}
          >
            <Icon className="w-[18px] h-[18px]" />
          </Link>
        ))}
      </nav>

      <div className="sidebar-footer">
        <button title="Settings" className="sidebar-item">
          <Settings className="w-[18px] h-[18px]" />
        </button>
      </div>
    </aside>
  );
}

"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import { ShieldIcon } from "@/components/ui/icons";
import { NAV_ITEMS, isActive } from "./nav-items";

/**
 * Primary navigation: a fixed sidebar on desktop, a scrollable top bar on
 * small screens.
 */
export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="border-line bg-surface flex shrink-0 flex-col border-b md:h-screen md:w-60 md:border-r md:border-b-0 md:sticky md:top-0">
      <div className="flex items-center gap-2 px-4 py-3 md:py-5">
        <ShieldIcon className="text-accent size-6" />
        <span className="font-semibold tracking-tight">SOC Dashboard</span>
      </div>

      <nav aria-label="Main" className="overflow-x-auto md:overflow-visible">
        <ul className="flex gap-1 px-2 pb-2 md:flex-col md:pb-0">
          {NAV_ITEMS.map(({ href, label, icon: Icon }) => {
            const active = isActive(href, pathname);
            return (
              <li key={href}>
                <Link
                  href={href}
                  aria-current={active ? "page" : undefined}
                  className={`flex items-center gap-3 whitespace-nowrap rounded-md px-3 py-2 text-sm transition-colors ${
                    active
                      ? "bg-surface-raised text-foreground font-medium"
                      : "text-muted hover:bg-surface-raised hover:text-foreground"
                  }`}
                >
                  <Icon className="size-4 shrink-0" />
                  {label}
                </Link>
              </li>
            );
          })}
        </ul>
      </nav>
    </aside>
  );
}

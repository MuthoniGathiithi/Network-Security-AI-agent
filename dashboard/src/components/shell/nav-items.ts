import type { ComponentType, SVGProps } from "react";

import {
  AlertIcon,
  BanIcon,
  GaugeIcon,
  ListIcon,
  RadioIcon,
  SettingsIcon,
  UploadIcon,
} from "@/components/ui/icons";

export type NavItem = {
  href: string;
  label: string;
  icon: ComponentType<SVGProps<SVGSVGElement>>;
};

export const NAV_ITEMS: NavItem[] = [
  { href: "/", label: "Overview", icon: GaugeIcon },
  { href: "/detections", label: "Detections", icon: AlertIcon },
  { href: "/analyze", label: "Analyze", icon: UploadIcon },
  { href: "/live", label: "Live capture", icon: RadioIcon },
  { href: "/blocklist", label: "Blocklist", icon: BanIcon },
  { href: "/activity", label: "Activity", icon: ListIcon },
  { href: "/settings", label: "Settings", icon: SettingsIcon },
];

/** Whether a nav item should be highlighted for the current path. */
export function isActive(href: string, pathname: string): boolean {
  return href === "/" ? pathname === "/" : pathname === href || pathname.startsWith(`${href}/`);
}

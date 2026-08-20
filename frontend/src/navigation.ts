/**
 * navigation.ts — next-intl v4 creates useRouter/usePathname via createNavigation.
 * These hooks keep locale switching client-side (no full page reload),
 * which is critical for preserving wagmi wallet session state.
 */
import { createNavigation } from "next-intl/navigation";
import { locales, defaultLocale } from "../i18n";

export const { Link, useRouter, usePathname, redirect, getPathname } =
  createNavigation({
    locales: Array.from(locales),
    defaultLocale,
  });

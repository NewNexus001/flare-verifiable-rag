"use client";

/**
 * LanguageSwitcher.tsx — dropdown language selector (Phase 19, P364/P365).
 *
 * Renders a dropdown with language flags and labels.
 * Language selection is persisted in localStorage and
 * switches the /[locale]/ route via next-intl router.
 */
import { useLocale, useTranslations } from "next-intl";
import { useRouter, usePathname } from "next/navigation";
import { useState, useRef, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Globe } from "lucide-react";
import type { Locale } from "../../i18n";

const LANGUAGES: { code: Locale; label: string; flag: string }[] = [
  { code: "en", label: "English", flag: "🇺🇸" },
  { code: "es", label: "Español", flag: "🇪🇸" },
  { code: "zh", label: "中文", flag: "🇨🇳" },
  { code: "ja", label: "日本語", flag: "🇯🇵" },
  { code: "ar", label: "العربية", flag: "🇸🇦" },
];

export function LanguageSwitcher() {
  const t = useTranslations("nav");
  const locale = useLocale();
  const router = useRouter();
  const pathname = usePathname();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  const current = LANGUAGES.find((l) => l.code === locale) ?? LANGUAGES[0];

  // Close dropdown on outside click
  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, []);

  function switchLanguage(code: Locale) {
    // Replace the locale segment in the current pathname
    const segments = pathname.split("/");
    // segments[0] = "", segments[1] = locale, segments[2+] = rest
    segments[1] = code;
    const newPath = segments.join("/") || `/${code}`;

    // Persist choice
    try {
      localStorage.setItem("vrag-locale", code);
    } catch {
      // localStorage unavailable (SSR / private mode) — silently ignore
    }

    router.push(newPath);
    setOpen(false);
  }

  return (
    <div ref={ref} style={{ position: "relative" }}>
      <motion.button
        type="button"
        whileHover={{ scale: 1.02 }}
        onClick={() => setOpen(!open)}
        aria-label="Select language"
        style={{
          display: "inline-flex",
          alignItems: "center",
          gap: "0.35rem",
          padding: "0.4rem 0.7rem",
          borderRadius: 999,
          border: "1px solid #2a3150",
          background: "rgba(255,255,255,0.04)",
          color: "#9aa3bf",
          fontSize: "0.78rem",
          fontWeight: 500,
          cursor: "pointer",
        }}
      >
        <Globe size={13} />
        <span>{current.flag}</span>
        <span style={{ fontSize: "0.72rem" }}>{current.code.toUpperCase()}</span>
      </motion.button>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0, y: -4, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -4, scale: 0.95 }}
            transition={{ duration: 0.15 }}
            style={{
              position: "absolute",
              top: "100%",
              right: 0,
              marginTop: 6,
              minWidth: 160,
              background: "#111827",
              border: "1px solid #1E293B",
              borderRadius: 12,
              boxShadow: "0 8px 32px rgba(0,0,0,0.4)",
              zIndex: 50,
              overflow: "hidden",
            }}
          >
            {LANGUAGES.map((lang) => (
              <button
                key={lang.code}
                type="button"
                onClick={() => switchLanguage(lang.code)}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "0.6rem",
                  width: "100%",
                  padding: "0.6rem 0.9rem",
                  border: "none",
                  background:
                    lang.code === locale
                      ? "rgba(56,189,248,0.1)"
                      : "transparent",
                  color: lang.code === locale ? "#38BDF8" : "#c0c8d8",
                  fontSize: "0.82rem",
                  cursor: "pointer",
                  textAlign: "left",
                }}
              >
                <span style={{ fontSize: "1.1rem" }}>{lang.flag}</span>
                <span>{lang.label}</span>
              </button>
            ))}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

"use client";

/**
 * not-found.tsx — custom 404 error page (Phase 19, P370).
 * Dark-mode terminal layout displaying security warnings.
 * Intercepts all unmatched routes with an obfuscated error page.
 */
import { useTranslations } from "next-intl";

export default function NotFound() {
  const t = useTranslations("notFound");

  return (
    <main
      style={{
        minHeight: "80vh",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        padding: "2rem",
        fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
        textAlign: "center",
      }}
    >
      <div
        style={{
          padding: "2rem 3rem",
          borderRadius: 16,
          border: "1px solid #E11D48",
          background: "rgba(225,29,72,0.06)",
          maxWidth: 480,
        }}
      >
        <h1
          style={{
            margin: "0 0 0.8rem",
            fontSize: "2rem",
            fontWeight: 800,
            color: "#E11D48",
            letterSpacing: "-0.02em",
          }}
        >
          404
        </h1>
        <p
          style={{
            margin: "0 0 1.2rem",
            fontSize: "0.95rem",
            color: "#9aa3bf",
            lineHeight: 1.6,
          }}
        >
          {t("message")}
        </p>
        <a
          href="/"
          style={{
            display: "inline-block",
            padding: "0.6rem 1.2rem",
            borderRadius: 8,
            border: "1px solid #38BDF8",
            background: "rgba(56,189,248,0.1)",
            color: "#38BDF8",
            fontSize: "0.85rem",
            fontWeight: 600,
            textDecoration: "none",
          }}
        >
          {t("backHome")}
        </a>
      </div>
    </main>
  );
}

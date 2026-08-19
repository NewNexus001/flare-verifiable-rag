"use client";

import { useRouter } from "next/navigation";
import { ArrowLeft } from "lucide-react";
import { useTranslations } from "next-intl";

export function BackButton() {
  const router = useRouter();
  const t = useTranslations();

  return (
    <button
      type="button"
      onClick={() => router.push("/")}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: "0.4rem",
        padding: "0.5rem 1rem",
        borderRadius: 10,
        border: "1px solid #2a3150",
        background: "rgba(255,255,255,0.04)",
        color: "#9aa3bf",
        fontSize: "0.85rem",
        fontWeight: 600,
        cursor: "pointer",
        marginBottom: "1.5rem",
      }}
    >
      <ArrowLeft size={15} />
      {t("nav.home")}
    </button>
  );
}

import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Flare Verifiable RAG — Verified AI Knowledge Oracle",
  description:
    "Verifiable Retrieval-Augmented Generation on Flare Coston2: hardware-attested enclave answers, client-side AES-GCM-256 encryption, on-chain price settlement.",
};

/**
 * Root layout — minimal wrapper. The actual providers and html/body
 * are in [locale]/layout.tsx. This root layout just renders children
 * (which will be the [locale] layout route group).
 */
export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return children;
}

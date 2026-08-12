import type { Metadata } from "next";
import ErrorBoundary from "@/components/ErrorBoundary";
import { Providers } from "./providers";
import "./globals.css";

export const metadata: Metadata = {
  title: "Flare Verifiable RAG — Verified AI Knowledge Oracle",
  description:
    "Verifiable Retrieval-Augmented Generation on Flare Coston2: hardware-attested enclave answers, client-side AES-GCM-256 encryption, on-chain price settlement.",
};

/**
 * Root layout (Phase 9 / Prompt 165). The application is wrapped in the
 * Web3 provider stack (Wagmi/QueryClient/RainbowKit, chain 114) and a
 * custom React ErrorBoundary that reports crashes through Sentry and shows
 * a "Report Bug" dialog.
 */
export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>
        <ErrorBoundary>
          <Providers>{children}</Providers>
        </ErrorBoundary>
      </body>
    </html>
  );
}

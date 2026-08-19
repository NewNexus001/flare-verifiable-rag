import type { Metadata } from "next";
import { NextIntlClientProvider } from "next-intl";
import { getMessages } from "next-intl/server";
import { notFound } from "next/navigation";
import ErrorBoundary from "@/components/ErrorBoundary";
import { DiagnosticsPanel } from "@/components/DiagnosticsPanel";
import { Header } from "@/components/Header";
import { CopilotDrawer } from "@/components/CopilotDrawer";
import { Providers } from "../providers";
import { locales, type Locale } from "../../../i18n";
import "../globals.css";

type Props = {
  children: React.ReactNode;
  params: { locale: string };
};

export const metadata: Metadata = {
  title: "Flare Verifiable RAG — Verified AI Knowledge Oracle",
  description:
    "Verifiable Retrieval-Augmented Generation on Flare Coston2: hardware-attested enclave answers, client-side AES-GCM-256 encryption, on-chain price settlement.",
};

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

export default async function LocaleLayout({ children, params }: Props) {
  const { locale } = await params;

  // Validate locale
  if (!locales.includes(locale as Locale)) {
    notFound();
  }

  const messages = await getMessages();
  const dir = locale === "ar" ? "rtl" : "ltr";

  return (
    <html lang={locale} dir={dir} suppressHydrationWarning>
      <body dir={dir}>
        <NextIntlClientProvider locale={locale} messages={messages}>
          <ErrorBoundary>
            <Providers>
              <Header />
              {children}
              <CopilotDrawer />
            </Providers>
          </ErrorBoundary>
          <DiagnosticsPanel />
        </NextIntlClientProvider>
      </body>
    </html>
  );
}

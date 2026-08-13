"use client";

/**
 * providers.tsx — Wagmi + QueryClient + RainbowKit provider stack,
 * configured for Flare Coston2 Testnet (chain id 114).
 *
 * The chain and RPC come from the environment with the canonical Coston2
 * RPC as the default (REAL-DATA-SOURCES.md — the same endpoint every other
 * phase uses). WalletConnect Cloud's projectId is OPTIONAL: when
 * NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID is absent the app connects through
 * browser-injected wallets only (injectedWallet = pure EIP-1193, no
 * third-party service).
 *
 * IMPORTANT (verified against rainbowkit@2.0.2 dist source): `metaMaskWallet`
 * and `walletConnectWallet` call `getWalletConnectConnector`, which THROWS
 * when projectId is empty. `injectedWallet` calls only `getInjectedConnector`
 * (no WalletConnect dependency), so it is the safe SSR/prerender choice when
 * no projectId is configured. With a projectId, WalletConnect + MetaMask
 * (incl. mobile deep-links) are unlocked.
 *
 * Error handling: wallet extensions (e.g. MetaMask) can reject a connection
 * with an unhandled promise rejection when the extension is locked or the
 * user cancels the modal. That rejection is caught here at the window level
 * and logged as a non-fatal event instead of surfacing as a Next.js dev
 * overlay crash — connection failures never take down the page.
 */
import "@rainbow-me/rainbowkit/styles.css";

import { RainbowKitProvider, connectorsForWallets } from "@rainbow-me/rainbowkit";
import {
  injectedWallet,
  metaMaskWallet,
  walletConnectWallet,
} from "@rainbow-me/rainbowkit/wallets";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { WagmiProvider, createConfig, http } from "wagmi";
import { flareTestnet } from "wagmi/chains"; // Coston2 = chain id 114

const projectId = process.env.NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID ?? "";

// getWalletConnectConnector throws on empty projectId — only include
// WalletConnect-dependent wallets when a real projectId is configured.
const wallets = projectId
  ? [walletConnectWallet, metaMaskWallet, injectedWallet]
  : [injectedWallet];

const connectors = connectorsForWallets(
  [{ groupName: "Recommended", wallets }],
  { appName: "Flare Verifiable RAG", projectId }
);

const wagmiConfig = createConfig({
  chains: [flareTestnet],
  connectors,
  transports: {
    [flareTestnet.id]: http(
      process.env.NEXT_PUBLIC_COSTON2_RPC_URL ??
        "https://coston2-api.flare.network/ext/C/rpc"
    ),
  },
  ssr: true,
});

/** Wallet connection failures surface as unhandled promise rejections when
 * the extension is locked or the user dismisses the modal. Swallow them at
 * the window boundary so a failed connection never crashes the page, while
 * keeping the message visible in the console for diagnostics. */
function installWalletErrorBoundary() {
  if (typeof window === "undefined") return;
  const handler = (event: PromiseRejectionEvent) => {
    const message = String(
      event?.reason?.message ?? event?.reason ?? ""
    ).toLowerCase();
    const isWalletRejection =
      message.includes("failed to connect") ||
      message.includes("user rejected") ||
      message.includes("user cancelled") ||
      message.includes("connector") ||
      message.includes("inpage");
    if (isWalletRejection) {
      // Prevent the rejection from reaching Next's dev overlay / global
      // error reporting; log it as a recoverable client event instead.
      event.preventDefault();
      console.info(
        "[wallet] connection attempt cancelled by the wallet extension:",
        event.reason
      );
    }
  };
  window.addEventListener("unhandledrejection", handler);
}

export function Providers({ children }: { children: React.ReactNode }) {
  const [queryClient] = useState(() => new QueryClient());

  useEffect(() => {
    installWalletErrorBoundary();
  }, []);

  return (
    <WagmiProvider config={wagmiConfig}>
      <QueryClientProvider client={queryClient}>
        <RainbowKitProvider coolMode modalSize="compact" locale="en-US">
          {children}
        </RainbowKitProvider>
      </QueryClientProvider>
    </WagmiProvider>
  );
}

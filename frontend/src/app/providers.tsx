"use client";

/**
 * providers.tsx — Wagmi + QueryClient + RainbowKit provider stack
 * (Phase 9 / Prompt 164), configured for Flare Coston2 Testnet (chain id 114).
 *
 * The chain and RPC come from the environment with the canonical verified
 * Coston2 RPC as the default (REAL-DATA-SOURCES.md — the same endpoint every
 * other phase uses). WalletConnect Cloud's projectId is OPTIONAL: when
 * NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID is absent the app connects through
 * browser-injected wallets only (injectedWallet = pure EIP-1193, no third-
 * party service) — no fabricated id (zero-mock policy).
 *
 * IMPORTANT (verified against rainbowkit@2.0.2 dist source): `metaMaskWallet`
 * and `walletConnectWallet` call `getWalletConnectConnector`, which THROWS
 * when projectId is empty. `injectedWallet` calls only `getInjectedConnector`
 * (no WalletConnect dependency), so it is the safe SSR/prerender choice when
 * no projectId is configured. With a projectId, WalletConnect + MetaMask
 * (incl. mobile deep-links) are unlocked.
 */
import "@rainbow-me/rainbowkit/styles.css";

import { RainbowKitProvider, connectorsForWallets } from "@rainbow-me/rainbowkit";
import {
  injectedWallet,
  metaMaskWallet,
  walletConnectWallet,
} from "@rainbow-me/rainbowkit/wallets";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState } from "react";
import { WagmiProvider, createConfig, http } from "wagmi";
import { flareTestnet } from "wagmi/chains"; // Coston2 = chain id 114 (empirically verified export name)

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

export function Providers({ children }: { children: React.ReactNode }) {
  const [queryClient] = useState(() => new QueryClient());

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

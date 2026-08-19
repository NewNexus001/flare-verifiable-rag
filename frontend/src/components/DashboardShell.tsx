"use client";

/**
 * DashboardShell.tsx — wraps all dashboard content with:
 * 1. WalletGate: blocks content until wallet is connected
 * 2. WalletConnectOverlay: animated connection flow with wallet logo + spinner
 */
import { useState, useEffect } from "react";
import { useAccount } from "wagmi";
import { WalletGate } from "@/components/WalletGate";
import { WalletConnectOverlay } from "@/components/WalletConnectOverlay";

export function DashboardShell({ children }: { children: React.ReactNode }) {
  const { isConnected, isConnecting } = useAccount();
  const [prevConnected, setPrevConnected] = useState(isConnected);
  const [justConnected, setJustConnected] = useState(false);

  // Track connection transitions for the overlay
  useEffect(() => {
    if (isConnected && !prevConnected) {
      // Just connected — show success overlay briefly
      setJustConnected(true);
      const t = setTimeout(() => setJustConnected(false), 2500);
      setPrevConnected(true);
      return () => clearTimeout(t);
    }
    if (!isConnected) {
      setPrevConnected(false);
      setJustConnected(false);
    }
  }, [isConnected, prevConnected]);

  return (
    <>
      {/* Animated wallet connection overlay */}
      <WalletConnectOverlay
        connecting={isConnecting}
        connected={isConnected}
      />

      {/* Gate: blocks everything until connected */}
      <WalletGate>{children}</WalletGate>
    </>
  );
}

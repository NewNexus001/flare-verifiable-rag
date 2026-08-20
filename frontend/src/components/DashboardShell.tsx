"use client";

/**
 * DashboardShell.tsx — wraps all dashboard content with:
 * 1. WalletGate: blocks content until wallet is connected
 * 2. WalletConnectOverlay: animated connection flow with wallet logo + spinner
 *
 * The overlay ONLY shows for user-initiated connections (not auto-reconnect).
 * This prevents the overlay from flashing on page reload or language switch.
 */
import { useState, useEffect, createContext, useContext } from "react";
import { useAccount } from "wagmi";
import { WalletGate } from "@/components/WalletGate";
import { WalletConnectOverlay } from "@/components/WalletConnectOverlay";

interface ConnectContextValue {
  requestConnect: () => void;
}

const ConnectContext = createContext<ConnectContextValue>({
  requestConnect: () => {},
});

/** Call this from any component to trigger the wallet overlay */
export function useRequestConnect() {
  return useContext(ConnectContext).requestConnect;
}

export function DashboardShell({ children }: { children: React.ReactNode }) {
  const { isConnected, isConnecting } = useAccount();
  const [userInitiated, setUserInitiated] = useState(false);

  // When the user explicitly triggers connect, show the overlay
  const requestConnect = () => {
    setUserInitiated(true);
  };

  // Reset user-initiated flag when connection completes or is cancelled
  useEffect(() => {
    if (isConnected) {
      // Keep showing overlay briefly for confirmed state
      const t = setTimeout(() => setUserInitiated(false), 1500);
      return () => clearTimeout(t);
    }
    if (!isConnecting && userInitiated) {
      // Connection was cancelled or failed — hide overlay
      setUserInitiated(false);
    }
  }, [isConnected, isConnecting, userInitiated]);

  // Only show overlay when user explicitly initiated the connection
  const showOverlay = userInitiated && (isConnecting || isConnected);

  return (
    <ConnectContext.Provider value={{ requestConnect }}>
      {/* Animated wallet connection overlay — only for user-initiated connect */}
      <WalletConnectOverlay
        connecting={showOverlay && isConnecting}
        connected={showOverlay && isConnected}
      />

      {/* Gate: blocks everything until connected */}
      <WalletGate>{children}</WalletGate>
    </ConnectContext.Provider>
  );
}

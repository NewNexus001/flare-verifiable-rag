/* eslint-disable */
// jest.setup.js — shared test bootstrap: jest-dom matchers + the jsdom
// polyfills Radix UI / framer-motion expect (ResizeObserver, matchMedia).
import "@testing-library/jest-dom";
import { TextDecoder, TextEncoder } from "util";

// jsdom (jest-environment-jsdom 29) does not expose Node's TextEncoder.
if (typeof globalThis.TextEncoder === "undefined") {
  globalThis.TextEncoder = TextEncoder;
  globalThis.TextDecoder = TextDecoder;
}

if (typeof globalThis.ResizeObserver === "undefined") {
  globalThis.ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  };
}

if (typeof window !== "undefined" && typeof window.matchMedia === "undefined") {
  window.matchMedia = (query) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => false,
  });
}

if (typeof window !== "undefined" && typeof window.scrollTo === "undefined") {
  window.scrollTo = () => {};
}

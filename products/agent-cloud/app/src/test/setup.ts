import "@testing-library/jest-dom/vitest";
import { vi } from "vitest";

Object.defineProperty(window, "scrollTo", {
  configurable: true,
  value: vi.fn(),
});

// jsdom deliberately omits canvas rendering. Axe probes this API while
// detecting icon ligatures, so provide the browser's valid "unsupported
// context" result instead of allowing jsdom to emit a misleading error during
// an otherwise clean accessibility gate.
Object.defineProperty(HTMLCanvasElement.prototype, "getContext", {
  configurable: true,
  value: vi.fn(() => null),
});

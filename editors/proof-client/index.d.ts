export type Lane = "review" | "architecture" | "security" | "runtime" | "forgeline";
export type State = "OBSERVED" | "FAILED" | "CANCELLED" | "TIMEOUT" | "INCOMPLETE" | "UNAVAILABLE" | "ERROR";
export interface Options { root: string; signal?: AbortSignal; timeoutMs?: number; maxBytes?: number; onOutput?: (text: string) => void; factory?: string; forge?: string; }
export interface Result { lane: Lane; label: string; state: State; detail: string; exitCode: number | null; durationMs: number; observedAt: string; candidateBinding: "UNBOUND"; limit: string; outputHash: string; report?: Record<string, unknown>; }
export const LANES: Record<Lane, { label: string; tool: string; args: string[]; limit: string }>;
export function redact(text: unknown): string;
export function runCommand(command: string, args: string[], options: Options): Promise<{state: State; stdout: string; stderr: string; exitCode: number | null; durationMs: number}>;
export function parseReport(stdout: string): Record<string, unknown>;
export function auditArgs(lane: Lane, root: string): string[];
export function audit(root: string, lane: Lane, options?: Omit<Options, "root">): Promise<Result>;
export function summary(results: Result[], stale?: boolean): string;
export function findings(result: Result): {message: string; severity: string; path?: string; line?: number}[];

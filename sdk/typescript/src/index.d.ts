export type PlanV2Input = Readonly<{
  id: string;
  executable: string;
  arguments: readonly string[];
  working_directory: string;
  read: readonly string[];
  runtime_read: readonly string[];
  write: readonly string[];
  execute: readonly string[];
  environment: readonly string[];
  processes: number | bigint;
  wall_time_ms: number | bigint;
  stdout_bytes: number | bigint;
  stderr_bytes: number | bigint;
  memory_bytes: number | bigint;
  swap_bytes: number | bigint;
}>;

export type RunOutcomeKind =
  | "exited"
  | "signaled"
  | "timed-out"
  | "denied"
  | "launcher-failed"
  | "incomplete";

export type RunResult = Readonly<{
  receipt: string;
  execution_id: Buffer;
  commitment: Buffer;
  outcome_kind: RunOutcomeKind;
  outcome_detail: number | null;
}>;

export type RunOptions = Readonly<{
  pbr: string;
  plan: string;
  receipt: string;
  cgroupRoot: string;
  environment: Readonly<Record<string, string>>;
  maxOutputBytes?: number;
}>;

export declare const version: "0.2.0";

export declare class SdkError extends Error {
  readonly code: string;
  readonly detail: string;
  constructor(code: string, detail?: string);
}

export declare function buildPlan(input: PlanV2Input): Buffer;
export declare function parseRunResult(value: Buffer | string): RunResult;
export declare function run(options: RunOptions): Promise<RunResult>;

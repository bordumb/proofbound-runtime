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
  network?: NetworkAuthorityV2Input;
}>;

export type NetworkAuthorityV2Input = "deny" | Readonly<{
  mode: "authenticated-service-session";
  service: Readonly<{ name: string; port: number | bigint }>;
  resolver: Readonly<{
    address: Readonly<{ family: "ipv4" | "ipv6"; bytes: Buffer }>;
    port: number | bigint;
    configuration: string;
    maximum_cname_depth: number | bigint;
    maximum_answer_count: number | bigint;
    maximum_response_bytes: number | bigint;
    resolution_deadline_ms: number | bigint;
    attempt_deadline_ms: number | bigint;
    address_order: "ipv4-then-ipv6-lexicographic";
  }>;
  tls: Readonly<{
    trust_root_set: string;
    minimum_version: "tls-1.2" | "tls-1.3";
    service_name_verification: "dns-san-exact";
    revocation: "not-checked-recorded-assumption";
    session_resumption: "deny";
    early_data: "deny";
  }>;
  limits: Readonly<{
    setup_time_ms: number | bigint;
    session_time_ms: number | bigint;
    child_to_service_bytes: number | bigint;
    service_to_child_bytes: number | bigint;
    dns_messages: number | bigint;
    endpoint_attempts: number | bigint;
    tls_handshake_bytes: number | bigint;
  }>;
  connector_executable: string;
  connector_runtime_read: readonly string[];
  local_channel: Readonly<{
    protocol: "unix-stream-v1";
    child_descriptor: number | bigint;
  }>;
  credential_source?: Readonly<{
    id: string;
    service: string;
    environment: string;
  }>;
}>;

export type PlanV3Input = Omit<PlanV2Input, "network"> & Readonly<{
  network: NetworkAuthorityV3Input;
}>;

export type NetworkAuthorityV3Input = Readonly<{
  mode: "declared-egress";
  endpoints: readonly Readonly<{
    destination: Readonly<{ kind: "dns-name"; name: string; address_scope: "global" | "global-or-private" }> |
      Readonly<{ kind: "ipv4" | "ipv6"; bytes: Buffer }>;
    port: number | bigint;
    protocol: "tcp";
    tls_sni: "not-inspected" | Readonly<{ mode: "required"; name: string }>;
  }>[];
  resolver: Readonly<{
    address: Readonly<{ family: "ipv4" | "ipv6"; bytes: Buffer }>;
    port: number | bigint;
    configuration: string;
    maximum_cname_depth: number | bigint;
    maximum_answer_count: number | bigint;
    maximum_response_bytes: number | bigint;
    resolution_deadline_ms: number | bigint;
    attempt_deadline_ms: number | bigint;
    address_order: "ipv4-then-ipv6-lexicographic";
  }>;
  limits: Readonly<{
    connections: number | bigint;
    concurrent_connections: number | bigint;
    attempts_per_connection: number | bigint;
    resolutions: number | bigint;
    dns_messages: number | bigint;
    client_to_remote_bytes: number | bigint;
    remote_to_client_bytes: number | bigint;
    connection_idle_ms: number | bigint;
  }>;
  proxy_executable: string;
  proxy_runtime_read: readonly string[];
  proxy_environment: readonly string[];
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
  resultVersion?: 2 | 3;
}>;

export declare const version: "0.2.0";

export declare class SdkError extends Error {
  readonly code: string;
  readonly detail: string;
  constructor(code: string, detail?: string);
}

export declare function buildPlan(input: PlanV2Input): Buffer;
export declare function buildPlanV3(input: PlanV3Input): Buffer;
export declare function parseRunResult(value: Buffer | string): RunResult;
export declare function parseRunResultV3(value: Buffer | string): RunResult;
export declare function run(options: RunOptions): Promise<RunResult>;

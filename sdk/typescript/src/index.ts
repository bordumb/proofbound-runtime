import { spawn } from "node:child_process";
import path from "node:path";

export const version = "0.2.0";
const PLAN_KEYS = [
  "arguments",
  "environment",
  "executable",
  "execute",
  "id",
  "memory_bytes",
  "processes",
  "read",
  "runtime_read",
  "stderr_bytes",
  "stdout_bytes",
  "swap_bytes",
  "wall_time_ms",
  "working_directory",
  "write",
];
const PLAN_KEYS_WITH_NETWORK = [...PLAN_KEYS, "network"].sort();
const RESULT_KEYS = ["commitment", "execution_id", "outcome", "receipt", "schema"];
const QUANTUM = 65_536n;
const MAX_RESOURCE = 1_099_511_627_776n;
const MAX_U64 = (1n << 64n) - 1n;
const MAX_U32 = (1n << 32n) - 1n;

export class SdkError extends Error {
  constructor(code, detail = "") {
    super(detail === "" ? code : code + ": " + detail);
    this.name = "SdkError";
    this.code = code;
    this.detail = detail;
  }
}

export function buildPlan(input) {
  requireExactKeys(
    input,
    Object.prototype.hasOwnProperty.call(input, "network")
      ? PLAN_KEYS_WITH_NETWORK
      : PLAN_KEYS,
    "sdk.plan.unknown-field",
  );
  if (
    typeof input.id !== "string" ||
    !/^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$/.test(input.id)
  ) {
    throw new SdkError("sdk.plan.id-invalid");
  }
  for (const name of [
    "arguments",
    "read",
    "runtime_read",
    "write",
    "execute",
    "environment",
  ]) {
    const values = input[name];
    if (!Array.isArray(values) || values.some((value) => typeof value !== "string" || value.includes("\0"))) {
      throw new SdkError("sdk.plan.field-invalid", name);
    }
    if (name !== "arguments" && new Set(values).size !== values.length) {
      throw new SdkError("sdk.plan.duplicate", name);
    }
  }
  for (const name of ["executable", "working_directory"]) {
    if (typeof input[name] !== "string" || input[name] === "" || input[name].includes("\0")) {
      throw new SdkError("sdk.plan.field-invalid", name);
    }
  }
  if (input.environment.some((name) => name === "" || name.includes("="))) {
    throw new SdkError("sdk.plan.field-invalid", "environment");
  }
  if (
    input.write.length !== 1 ||
    input.execute.length !== 1 ||
    input.execute[0] !== input.executable
  ) {
    throw new SdkError("sdk.plan.shape-invalid");
  }
  if (input.runtime_read.some((value) => !path.isAbsolute(value))) {
    throw new SdkError("sdk.plan.runtime-read-not-absolute");
  }
  const processes = unsigned(input.processes, 1n, MAX_U32, "processes");
  const wallTime = unsigned(input.wall_time_ms, 1n, MAX_U64, "wall_time_ms");
  const stdout = unsigned(input.stdout_bytes, 0n, MAX_U64, "stdout_bytes");
  const stderr = unsigned(input.stderr_bytes, 0n, MAX_U64, "stderr_bytes");
  const memory = unsigned(input.memory_bytes, QUANTUM, MAX_RESOURCE, "memory_bytes");
  const swap = unsigned(input.swap_bytes, 0n, MAX_RESOURCE, "swap_bytes");
  if (memory % QUANTUM !== 0n || swap % QUANTUM !== 0n) {
    throw new SdkError("sdk.plan.limit-not-quantized");
  }
  const network = validateNetwork(input.network ?? "deny", input.environment);
  return encode({
    id: input.id,
    schema: "proofbound-runtime-plan/2",
    limits: {
      processes,
      swap_bytes: swap,
      stderr_bytes: stderr,
      stdout_bytes: stdout,
      memory_bytes: memory,
      wall_time_ms: wallTime,
    },
    command: {
      arguments: input.arguments,
      executable: input.executable,
      working_directory: input.working_directory,
    },
    authority: {
      read: input.read,
      write: input.write,
      execute: input.execute,
      network,
      environment: input.environment,
      runtime_read: input.runtime_read,
    },
  });
}

export function buildPlanV3(input) {
  const expected = [...PLAN_KEYS.filter((key) => key !== "network"), "network"].sort();
  requireExactKeys(input, expected, "sdk.plan.unknown-field");
  if (!Array.isArray(input.execute) || input.execute.length < 1 || input.execute.length > 64 ||
      input.execute.some((entry) => typeof entry !== "string" || entry === "" || entry.includes("\0")) ||
      new Set(input.execute).size !== input.execute.length || !input.execute.includes(input.executable)) {
    throw new SdkError("sdk.plan.shape-invalid");
  }
  buildPlan({ ...input, execute: [input.executable], network: "deny" });
  const network = validateEgressNetwork(input.network, input.environment);
  return encode({
    id: input.id,
    schema: "proofbound-runtime-plan/3",
    limits: {
      processes: unsigned(input.processes, 1n, MAX_U32, "processes"),
      wall_time_ms: unsigned(input.wall_time_ms, 1n, MAX_U64, "wall_time_ms"),
      stdout_bytes: unsigned(input.stdout_bytes, 0n, MAX_U64, "stdout_bytes"),
      stderr_bytes: unsigned(input.stderr_bytes, 0n, MAX_U64, "stderr_bytes"),
      memory_bytes: unsigned(input.memory_bytes, QUANTUM, MAX_RESOURCE, "memory_bytes"),
      swap_bytes: unsigned(input.swap_bytes, 0n, MAX_RESOURCE, "swap_bytes"),
    },
    command: { arguments: [...input.arguments], executable: input.executable,
      working_directory: input.working_directory },
    authority: { read: [...input.read], runtime_read: [...input.runtime_read],
      write: [...input.write], execute: [...input.execute].sort(),
      environment: [...input.environment], network },
  });
}

function validEgressName(value) {
  return validServiceName(value) && value.includes(".") && !/^[0-9]+$/.test(value.split(".").at(-1));
}

function validateEgressNetwork(value, environment) {
  const bad = (field) => { throw new SdkError("sdk.plan.network-invalid", field); };
  requireExactKeys(value, ["endpoints", "limits", "mode", "proxy_environment", "proxy_executable", "proxy_runtime_read", "resolver"], "sdk.plan.network-invalid");
  if (value.mode !== "declared-egress" || !Array.isArray(value.endpoints) ||
      value.endpoints.length < 1 || value.endpoints.length > 256) bad("endpoints");
  const seen = new Set();
  const scopes = new Map();
  const endpoints = value.endpoints.map((item) => {
    requireExactKeys(item, ["destination", "port", "protocol", "tls_sni"], "sdk.plan.network-invalid");
    const port = networkUnsigned(item.port, 1n, 65_535n, "endpoint.port");
    const destination = item.destination;
    if (destination === null || typeof destination !== "object" || Array.isArray(destination)) bad("endpoint.destination");
    let order;
    let identity;
    if (destination.kind === "dns-name") {
      requireExactKeys(destination, ["address_scope", "kind", "name"], "sdk.plan.network-invalid");
      if (!validEgressName(destination.name) || !["global", "global-or-private"].includes(destination.address_scope)) bad("endpoint.name");
      if (scopes.has(destination.name) && scopes.get(destination.name) !== destination.address_scope) bad("endpoint.scope");
      scopes.set(destination.name, destination.address_scope);
      order = [0, destination.name, destination.address_scope === "global" ? 0 : 1];
      identity = "dns:" + destination.name;
    } else if (destination.kind === "ipv4" || destination.kind === "ipv6") {
      requireExactKeys(destination, ["bytes", "kind"], "sdk.plan.network-invalid");
      const width = destination.kind === "ipv4" ? 4 : 16;
      const bytes = destination.bytes;
      if (!Buffer.isBuffer(bytes) || bytes.length !== width || bytes.every((byte) => byte === 0) ||
          (width === 4 && (bytes[0] >= 224 || bytes.every((byte) => byte === 255))) ||
          (width === 16 && (bytes[0] === 255 ||
            (bytes.subarray(0, 12).every((byte) => byte === 0) &&
              !(bytes.subarray(12, 15).every((byte) => byte === 0) && bytes[15] === 1)) ||
            (bytes.subarray(0, 10).every((byte) => byte === 0) && bytes[10] === 255 && bytes[11] === 255)))) bad("endpoint.address");
      order = [width === 4 ? 1 : 2, bytes.toString("hex")];
      identity = destination.kind + ":" + bytes.toString("hex");
    } else bad("endpoint.kind");
    if (item.protocol !== "tcp" || seen.has(identity + ":" + port)) bad("endpoint.conflict");
    seen.add(identity + ":" + port);
    let sni = item.tls_sni;
    if (sni !== "not-inspected") {
      requireExactKeys(sni, ["mode", "name"], "sdk.plan.network-invalid");
      if (sni.mode !== "required" || !validEgressName(sni.name) ||
          (destination.kind === "dns-name" && sni.name !== destination.name)) bad("endpoint.tls_sni");
    }
    return { value: { destination, port, protocol: "tcp", tls_sni: sni },
      order: [...order, Number(port), sni === "not-inspected" ? 0 : 1, sni === "not-inspected" ? "" : sni.name] };
  });
  endpoints.sort((left, right) => {
    for (let index = 0; index < Math.max(left.order.length, right.order.length); index += 1) {
      if (left.order[index] < right.order[index]) return -1;
      if (left.order[index] > right.order[index]) return 1;
    }
    return 0;
  });
  const resolver = value.resolver;
  requireExactKeys(resolver, ["address", "address_order", "attempt_deadline_ms", "configuration", "maximum_answer_count", "maximum_cname_depth", "maximum_response_bytes", "port", "resolution_deadline_ms"], "sdk.plan.network-invalid");
  requireExactKeys(resolver.address, ["bytes", "family"], "sdk.plan.network-invalid");
  const width = resolver.address.family === "ipv4" ? 4 : resolver.address.family === "ipv6" ? 16 : 0;
  if (!width || !Buffer.isBuffer(resolver.address.bytes) || resolver.address.bytes.length !== width ||
      !canonicalAbsolute(resolver.configuration) || resolver.address_order !== "ipv4-then-ipv6-lexicographic") bad("resolver");
  const normalizedResolver = { ...resolver,
    port: networkUnsigned(resolver.port, 1n, 65_535n, "resolver.port"),
    maximum_cname_depth: networkUnsigned(resolver.maximum_cname_depth, 1n, 4n, "resolver.maximum_cname_depth"),
    maximum_answer_count: networkUnsigned(resolver.maximum_answer_count, 1n, 16n, "resolver.maximum_answer_count"),
    maximum_response_bytes: networkUnsigned(resolver.maximum_response_bytes, 1n, 65_535n, "resolver.maximum_response_bytes"),
    resolution_deadline_ms: networkUnsigned(resolver.resolution_deadline_ms, 1n, 60_000n, "resolver.resolution_deadline_ms"),
    attempt_deadline_ms: networkUnsigned(resolver.attempt_deadline_ms, 1n, 60_000n, "resolver.attempt_deadline_ms") };
  if (normalizedResolver.attempt_deadline_ms > normalizedResolver.resolution_deadline_ms) bad("resolver.deadline");
  const limits = value.limits;
  requireExactKeys(limits, ["attempts_per_connection", "client_to_remote_bytes", "concurrent_connections", "connection_idle_ms", "connections", "dns_messages", "remote_to_client_bytes", "resolutions"], "sdk.plan.network-invalid");
  const normalizedLimits = {};
  for (const [field, minimum, maximum] of [
    ["connections", 1n, 8192n], ["concurrent_connections", 1n, 512n],
    ["attempts_per_connection", 1n, 4n], ["resolutions", 1n, 1024n],
    ["dns_messages", 2n, 8192n], ["client_to_remote_bytes", 1n, 1n << 40n],
    ["remote_to_client_bytes", 1n, 1n << 40n], ["connection_idle_ms", 1n, 3_600_000n],
  ]) normalizedLimits[field] = networkUnsigned(limits[field], minimum, maximum, "limits." + field);
  if (normalizedLimits.attempts_per_connection > normalizedResolver.maximum_answer_count) bad("limits.attempts_per_connection");
  if (!canonicalAbsolute(value.proxy_executable) || !Array.isArray(value.proxy_runtime_read) ||
      value.proxy_runtime_read.some((entry) => !canonicalAbsolute(entry))) bad("proxy_runtime_read");
  const variables = value.proxy_environment;
  const allowed = new Set(["ALL_PROXY", "HTTP_PROXY", "HTTPS_PROXY", "all_proxy", "http_proxy", "https_proxy"]);
  if (!Array.isArray(variables) || variables.length < 1 || variables.length > 6 ||
      variables.some((entry) => !allowed.has(entry)) || variables.join("\0") !== [...new Set(variables)].sort().join("\0") ||
      environment.some((name) => ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"].includes(name.toUpperCase()))) bad("proxy_environment");
  return { mode: "declared-egress", endpoints: endpoints.map((entry) => entry.value),
    resolver: normalizedResolver, limits: normalizedLimits,
    proxy_executable: value.proxy_executable,
    proxy_runtime_read: [...new Set(value.proxy_runtime_read)].sort(),
    proxy_environment: [...variables] };
}

function validateNetwork(value, environment) {
  if (value === "deny") return "deny";
  requireExactOrOptionalKeys(
    value,
    [
      "connector_executable",
      "connector_runtime_read",
      "limits",
      "local_channel",
      "mode",
      "resolver",
      "service",
      "tls",
    ],
    ["credential_source"],
    "sdk.plan.network-invalid",
  );
  if (value.mode !== "authenticated-service-session") {
    throw new SdkError("sdk.plan.network-invalid", "mode");
  }
  requireExactKeys(value.service, ["name", "port"], "sdk.plan.network-invalid");
  if (!validServiceName(value.service.name)) {
    throw new SdkError("sdk.plan.network-invalid", "service.name");
  }
  const servicePort = networkUnsigned(value.service.port, 1n, 65_535n, "service.port");

  requireExactKeys(
    value.resolver,
    [
      "address",
      "address_order",
      "attempt_deadline_ms",
      "configuration",
      "maximum_answer_count",
      "maximum_cname_depth",
      "maximum_response_bytes",
      "port",
      "resolution_deadline_ms",
    ],
    "sdk.plan.network-invalid",
  );
  requireExactKeys(value.resolver.address, ["bytes", "family"], "sdk.plan.network-invalid");
  const addressSize = { ipv4: 4, ipv6: 16 }[value.resolver.address.family];
  if (!addressSize || !Buffer.isBuffer(value.resolver.address.bytes) || value.resolver.address.bytes.length !== addressSize) {
    throw new SdkError("sdk.plan.network-invalid", "resolver.address");
  }
  const resolverPort = networkUnsigned(value.resolver.port, 1n, 65_535n, "resolver.port");
  if (!canonicalAbsolute(value.resolver.configuration)) {
    throw new SdkError("sdk.plan.network-invalid", "resolver.configuration");
  }
  const maximumCnameDepth = networkUnsigned(value.resolver.maximum_cname_depth, 1n, 65_535n, "resolver.maximum_cname_depth");
  const maximumAnswerCount = networkUnsigned(value.resolver.maximum_answer_count, 1n, 65_535n, "resolver.maximum_answer_count");
  const maximumResponseBytes = networkUnsigned(value.resolver.maximum_response_bytes, 1n, MAX_U64, "resolver.maximum_response_bytes");
  const resolutionDeadline = networkUnsigned(value.resolver.resolution_deadline_ms, 1n, MAX_U64, "resolver.resolution_deadline_ms");
  const attemptDeadline = networkUnsigned(value.resolver.attempt_deadline_ms, 1n, MAX_U64, "resolver.attempt_deadline_ms");
  if (attemptDeadline > resolutionDeadline || value.resolver.address_order !== "ipv4-then-ipv6-lexicographic") {
    throw new SdkError("sdk.plan.network-invalid", "resolver");
  }

  requireExactKeys(
    value.tls,
    [
      "early_data",
      "minimum_version",
      "revocation",
      "service_name_verification",
      "session_resumption",
      "trust_root_set",
    ],
    "sdk.plan.network-invalid",
  );
  if (
    !canonicalAbsolute(value.tls.trust_root_set) ||
    !["tls-1.2", "tls-1.3"].includes(value.tls.minimum_version) ||
    value.tls.service_name_verification !== "dns-san-exact" ||
    value.tls.revocation !== "not-checked-recorded-assumption" ||
    value.tls.session_resumption !== "deny" ||
    value.tls.early_data !== "deny"
  ) {
    throw new SdkError("sdk.plan.network-invalid", "tls");
  }

  requireExactKeys(
    value.limits,
    [
      "child_to_service_bytes",
      "dns_messages",
      "endpoint_attempts",
      "service_to_child_bytes",
      "session_time_ms",
      "setup_time_ms",
      "tls_handshake_bytes",
    ],
    "sdk.plan.network-invalid",
  );
  const limits = {
    setup_time_ms: networkUnsigned(value.limits.setup_time_ms, 1n, MAX_U64, "limits.setup_time_ms"),
    session_time_ms: networkUnsigned(value.limits.session_time_ms, 1n, MAX_U64, "limits.session_time_ms"),
    child_to_service_bytes: networkUnsigned(value.limits.child_to_service_bytes, 1n, MAX_U64, "limits.child_to_service_bytes"),
    service_to_child_bytes: networkUnsigned(value.limits.service_to_child_bytes, 1n, MAX_U64, "limits.service_to_child_bytes"),
    dns_messages: networkUnsigned(value.limits.dns_messages, 2n, 65_535n, "limits.dns_messages"),
    endpoint_attempts: networkUnsigned(value.limits.endpoint_attempts, 1n, 65_535n, "limits.endpoint_attempts"),
    tls_handshake_bytes: networkUnsigned(value.limits.tls_handshake_bytes, 1n, MAX_U64, "limits.tls_handshake_bytes"),
  };
  if (limits.endpoint_attempts > maximumAnswerCount) {
    throw new SdkError("sdk.plan.network-invalid", "limits.endpoint_attempts");
  }
  if (resolutionDeadline > limits.setup_time_ms) {
    throw new SdkError("sdk.plan.network-invalid", "limits.setup_time_ms");
  }
  if (!canonicalAbsolute(value.connector_executable)) {
    throw new SdkError("sdk.plan.network-invalid", "connector_executable");
  }
  if (
    !Array.isArray(value.connector_runtime_read) ||
    new Set(value.connector_runtime_read).size !== value.connector_runtime_read.length ||
    value.connector_runtime_read.some((entry) => !canonicalAbsolute(entry))
  ) {
    throw new SdkError("sdk.plan.network-invalid", "connector_runtime_read");
  }
  requireExactKeys(value.local_channel, ["child_descriptor", "protocol"], "sdk.plan.network-invalid");
  if (value.local_channel.protocol !== "unix-stream-v1") {
    throw new SdkError("sdk.plan.network-invalid", "local_channel.protocol");
  }
  const childDescriptor = networkUnsigned(value.local_channel.child_descriptor, 3n, 65_535n, "local_channel.child_descriptor");

  let credentialSource;
  if (Object.prototype.hasOwnProperty.call(value, "credential_source")) {
    requireExactKeys(value.credential_source, ["environment", "id", "service"], "sdk.plan.network-invalid");
    if (
      typeof value.credential_source.id !== "string" ||
      !/^[a-z](?:[a-z0-9.-]{0,126}[a-z0-9])?$/.test(value.credential_source.id) ||
      value.credential_source.service !== value.service.name ||
      !environment.includes(value.credential_source.environment)
    ) {
      throw new SdkError("sdk.plan.network-invalid", "credential_source");
    }
    credentialSource = { ...value.credential_source };
  }
  const result = {
    mode: value.mode,
    service: { name: value.service.name, port: servicePort },
    resolver: {
      address: { family: value.resolver.address.family, bytes: value.resolver.address.bytes },
      port: resolverPort,
      configuration: value.resolver.configuration,
      maximum_cname_depth: maximumCnameDepth,
      maximum_answer_count: maximumAnswerCount,
      maximum_response_bytes: maximumResponseBytes,
      resolution_deadline_ms: resolutionDeadline,
      attempt_deadline_ms: attemptDeadline,
      address_order: value.resolver.address_order,
    },
    tls: { ...value.tls },
    limits,
    connector_executable: value.connector_executable,
    connector_runtime_read: [...value.connector_runtime_read],
    local_channel: { protocol: value.local_channel.protocol, child_descriptor: childDescriptor },
  };
  return credentialSource === undefined
    ? result
    : { ...result, credential_source: credentialSource };
}

function networkUnsigned(value, minimum, maximum, name) {
  try {
    return unsigned(value, minimum, maximum, name);
  } catch (_error) {
    throw new SdkError("sdk.plan.network-invalid", name);
  }
}

function canonicalAbsolute(value) {
  return typeof value === "string" &&
    !value.includes("\0") &&
    path.posix.isAbsolute(value) &&
    (value === "/" || (
      !value.endsWith("/") &&
      !value.slice(1).split("/").some((part) => part === "" || part === "." || part === "..")
    ));
}

function validServiceName(value) {
  if (typeof value !== "string" || value.length < 1 || value.length > 253 || value.endsWith(".")) return false;
  if (/^[0-9.]+$/.test(value) || value.includes(":")) return false;
  return value.split(".").every((label) =>
    label.length >= 1 && label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)
  );
}

export function parseRunResult(value) {
  return parseRunResultSchema(value, "proofbound-runtime-run-result/2");
}

export function parseRunResultV3(value) {
  return parseRunResultSchema(value, "proofbound-runtime-run-result/3");
}

function parseRunResultSchema(value, schema) {
  let decoded;
  try {
    decoded = JSON.parse(Buffer.isBuffer(value) ? value.toString("utf8") : value);
  } catch (_error) {
    throw new SdkError("sdk.result.malformed-json");
  }
  requireExactKeys(decoded, RESULT_KEYS, "sdk.result.unknown-field");
  if (decoded.schema !== schema) {
    throw new SdkError("sdk.result.schema-unsupported");
  }
  if (typeof decoded.receipt !== "string" || decoded.receipt === "") {
    throw new SdkError("sdk.result.field-invalid", "receipt");
  }
  const commitment = decodeHex(decoded.commitment, 32);
  const executionId = decodeHex(decoded.execution_id, 16);
  if (executionId[6] >> 4 !== 4 || executionId[8] >> 6 !== 2) {
    throw new SdkError("sdk.result.field-invalid", "execution_id");
  }
  const outcome = decodeOutcome(decoded.outcome);
  return Object.freeze({
    receipt: decoded.receipt,
    execution_id: executionId,
    commitment,
    outcome_kind: outcome.kind,
    outcome_detail: outcome.detail,
  });
}

export function run({
  pbr,
  plan,
  receipt,
  cgroupRoot,
  environment,
  maxOutputBytes = 1_048_576,
  resultVersion = 2,
}) {
  if (resultVersion !== 2 && resultVersion !== 3) {
    return Promise.reject(new SdkError("sdk.result.schema-unsupported"));
  }
  for (const value of [pbr, plan, receipt, cgroupRoot]) {
    if (typeof value !== "string" || !path.isAbsolute(value)) {
      return Promise.reject(new SdkError("sdk.process.path-not-absolute"));
    }
  }
  if (
    !Number.isSafeInteger(maxOutputBytes) ||
    maxOutputBytes < 1 ||
    maxOutputBytes > 16_777_216
  ) {
    return Promise.reject(new SdkError("sdk.process.bound-invalid"));
  }
  if (
    environment === null ||
    typeof environment !== "object" ||
    Array.isArray(environment) ||
    Object.entries(environment).some(
      ([name, value]) =>
        name === "" ||
        name.includes("=") ||
        name.includes("\0") ||
        typeof value !== "string" ||
        value.includes("\0"),
    )
  ) {
    return Promise.reject(new SdkError("sdk.process.environment-invalid"));
  }
  const argumentsList = [
    "run",
    "--plan",
    plan,
    "--receipt",
    receipt,
    "--cgroup-root",
    cgroupRoot,
  ];
  return new Promise((resolve, reject) => {
    let settled = false;
    let stdout = Buffer.alloc(0);
    let stderr = Buffer.alloc(0);
    const child = spawn(pbr, argumentsList, {
      env: { ...environment },
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const fail = (error) => {
      if (!settled) {
        settled = true;
        reject(error);
      }
    };
    const append = (stream, chunk) => {
      const combined = Buffer.concat([stream, chunk]);
      if (combined.length > maxOutputBytes) {
        child.kill("SIGKILL");
        fail(new SdkError("sdk.process.output-bound"));
      }
      return combined;
    };
    child.once("error", () => fail(new SdkError("sdk.process.start-failed")));
    child.stdout.on("data", (chunk) => {
      if (!settled) stdout = append(stdout, chunk);
    });
    child.stderr.on("data", (chunk) => {
      if (!settled) stderr = append(stderr, chunk);
    });
    child.once("close", (code, signal) => {
      if (settled) return;
      if (code !== 0) {
        fail(
          new SdkError(
            "sdk.process.failed",
            "exit=" + String(code) + " signal=" + String(signal) +
              " stderr=" + stderr.toString("utf8").replace(/\n$/, ""),
          ),
        );
        return;
      }
      if (stdout.length === 0 || stdout[stdout.length - 1] !== 10 || stdout.subarray(0, -1).includes(10)) {
        fail(new SdkError("sdk.result.not-one-line"));
        return;
      }
      try {
        const result = resultVersion === 2 ? parseRunResult(stdout.subarray(0, -1)) : parseRunResultV3(stdout.subarray(0, -1));
        settled = true;
        resolve(result);
      } catch (error) {
        fail(error);
      }
    });
  });
}

function unsigned(value, minimum, maximum, name) {
  let result;
  if (typeof value === "bigint") {
    result = value;
  } else if (typeof value === "number" && Number.isSafeInteger(value)) {
    result = BigInt(value);
  } else {
    throw new SdkError("sdk.plan.limit-invalid", name);
  }
  if (result < minimum || result > maximum) {
    throw new SdkError("sdk.plan.limit-invalid", name);
  }
  return result;
}

function encodeArgument(major, value) {
  if (value < 24n) return Buffer.from([(major << 5) | Number(value)]);
  for (const [additional, width] of [[24, 1], [25, 2], [26, 4], [27, 8]]) {
    if (value < 1n << BigInt(width * 8)) {
      const output = Buffer.alloc(1 + width);
      output[0] = (major << 5) | additional;
      for (let index = 0; index < width; index += 1) {
        const shift = BigInt((width - index - 1) * 8);
        output[index + 1] = Number((value >> shift) & 0xffn);
      }
      return output;
    }
  }
  throw new SdkError("sdk.plan.cbor-bound");
}

function encode(value) {
  if (Buffer.isBuffer(value)) {
    return Buffer.concat([encodeArgument(2, BigInt(value.length)), value]);
  }
  if (typeof value === "string") {
    const payload = Buffer.from(value, "utf8");
    return Buffer.concat([encodeArgument(3, BigInt(payload.length)), payload]);
  }
  if (typeof value === "bigint" && value >= 0n) return encodeArgument(0, value);
  if (Array.isArray(value)) {
    return Buffer.concat([
      encodeArgument(4, BigInt(value.length)),
      ...value.map((item) => encode(item)),
    ]);
  }
  if (value !== null && typeof value === "object") {
    const entries = Object.entries(value)
      .map(([key, item]) => [encode(key), encode(item)])
      .sort(([left], [right]) => Buffer.compare(left, right));
    return Buffer.concat([
      encodeArgument(5, BigInt(entries.length)),
      ...entries.flatMap(([key, item]) => [key, item]),
    ]);
  }
  throw new SdkError("sdk.plan.field-invalid");
}

function requireExactKeys(value, expected, code) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new SdkError(code);
  }
  const actual = Object.keys(value).sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new SdkError(code);
  }
}

function requireExactOrOptionalKeys(value, required, optional, code) {
  if (value === null || typeof value !== "object" || Array.isArray(value) || Buffer.isBuffer(value)) {
    throw new SdkError(code);
  }
  const actual = Object.keys(value);
  if (!required.every((key) => actual.includes(key)) || actual.some((key) => !required.includes(key) && !optional.includes(key))) {
    throw new SdkError(code);
  }
}

function decodeHex(value, size) {
  if (
    typeof value !== "string" ||
    !new RegExp("^hex:[0-9a-f]{" + String(size * 2) + "}$").test(value)
  ) {
    throw new SdkError("sdk.result.field-invalid");
  }
  return Buffer.from(value.slice(4), "hex");
}

function decodeOutcome(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value) || typeof value.kind !== "string") {
    throw new SdkError("sdk.result.field-invalid", "outcome");
  }
  if (value.kind === "exited") {
    requireExactKeys(value, ["code", "kind"], "sdk.result.unknown-field");
    if (!Number.isInteger(value.code) || value.code < 0 || value.code > 255) {
      throw new SdkError("sdk.result.field-invalid", "outcome");
    }
    return { kind: value.kind, detail: value.code };
  }
  if (value.kind === "signaled") {
    requireExactKeys(value, ["kind", "signal"], "sdk.result.unknown-field");
    if (!Number.isInteger(value.signal) || value.signal < 1 || value.signal > 255) {
      throw new SdkError("sdk.result.field-invalid", "outcome");
    }
    return { kind: value.kind, detail: value.signal };
  }
  if (["timed-out", "denied", "launcher-failed", "incomplete"].includes(value.kind)) {
    requireExactKeys(value, ["kind"], "sdk.result.unknown-field");
    return { kind: value.kind, detail: null };
  }
  throw new SdkError("sdk.result.field-invalid", "outcome");
}

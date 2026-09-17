import assert from "node:assert/strict";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  SdkError,
  buildPlan,
  parseRunResult,
  run,
} from "../src/index.ts";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const resultText = '{"schema":"proofbound-runtime-run-result/2","outcome":{"kind":"exited","code":0},"receipt":"receipt.cbor","commitment":"hex:0909090909090909090909090909090909090909090909090909090909090909","execution_id":"hex:00000000000040008000000000000000"}';

function goldenPlan() {
  return {
    id: "golden-v2",
    executable: "bin/hello",
    arguments: [],
    working_directory: ".",
    read: [],
    runtime_read: [],
    write: ["out"],
    execute: ["bin/hello"],
    environment: [],
    processes: 2,
    wall_time_ms: 1_000,
    stdout_bytes: 1_024,
    stderr_bytes: 1_024,
    memory_bytes: 65_536,
    swap_bytes: 0,
  };
}

function serviceNetwork() {
  return {
    mode: "authenticated-service-session",
    service: { name: "api.anthropic.com", port: 443 },
    resolver: {
      address: { family: "ipv4", bytes: Buffer.from([1, 1, 1, 1]) },
      port: 53,
      configuration: "/etc/proofbound/resolver.conf",
      maximum_cname_depth: 8,
      maximum_answer_count: 16,
      maximum_response_bytes: 65_536,
      resolution_deadline_ms: 5_000,
      attempt_deadline_ms: 1_000,
      address_order: "ipv4-then-ipv6-lexicographic",
    },
    tls: {
      trust_root_set: "/etc/ssl/certs/ca-certificates.crt",
      minimum_version: "tls-1.3",
      service_name_verification: "dns-san-exact",
      revocation: "not-checked-recorded-assumption",
      session_resumption: "deny",
      early_data: "deny",
    },
    limits: {
      setup_time_ms: 10_000,
      session_time_ms: 30_000,
      child_to_service_bytes: 1_048_576,
      service_to_child_bytes: 1_048_576,
      dns_messages: 4,
      endpoint_attempts: 4,
      tls_handshake_bytes: 262_144,
    },
    connector_executable: "/usr/libexec/proofbound-connector",
    connector_runtime_read: ["/usr/lib"],
    local_channel: { protocol: "unix-stream-v1", child_descriptor: 9 },
    credential_source: {
      id: "anthropic-test",
      service: "api.anthropic.com",
      environment: "API_KEY",
    },
  };
}

test("TypeScript plan matches the frozen v2 golden", async () => {
  const expectedHex = (
    await readFile(
      path.join(repositoryRoot, "schemas/vectors/v2/execution-plan.cbor.hex"),
      "utf8",
    )
  ).replace(/\s/g, "");
  assert.equal(buildPlan(goldenPlan()).toString("hex"), expectedHex);
});

test("unknown and invalid plan fields fail before encoding", () => {
  assert.throws(
    () => buildPlan({ ...goldenPlan(), unknown: "deny" }),
    (error) => error instanceof SdkError && error.code === "sdk.plan.unknown-field",
  );
  assert.throws(
    () => buildPlan({ ...goldenPlan(), memory_bytes: 65_537 }),
    (error) => error instanceof SdkError && error.code === "sdk.plan.limit-not-quantized",
  );
});

test("service session is closed and validated", async () => {
  const plan = {
    ...goldenPlan(),
    environment: ["API_KEY"],
    network: serviceNetwork(),
  };
  const expectedHex = (
    await readFile(
      path.join(repositoryRoot, "schemas/vectors/v2/execution-plan-service-session.cbor.hex"),
      "utf8",
    )
  ).replace(/\s/g, "");
  assert.equal(buildPlan(plan).toString("hex"), expectedHex);
  assert.throws(
    () => buildPlan({
      ...plan,
      network: {
        ...serviceNetwork(),
        service: { name: "API.anthropic.com", port: 443 },
      },
    }),
    (error) => error instanceof SdkError && error.code === "sdk.plan.network-invalid",
  );
  const shortSetup = serviceNetwork();
  shortSetup.limits.setup_time_ms = 4_999;
  assert.throws(
    () => buildPlan({ ...plan, network: shortSetup }),
    (error) => error instanceof SdkError && error.code === "sdk.plan.network-invalid",
  );
  const numericName = serviceNetwork();
  numericName.service.name = "001.002.003.004";
  assert.throws(
    () => buildPlan({ ...plan, network: numericName }),
    (error) => error instanceof SdkError && error.code === "sdk.plan.network-invalid",
  );
});

test("run-result projection is closed", () => {
  const result = parseRunResult(resultText);
  assert.equal(result.receipt, "receipt.cbor");
  assert.equal(result.outcome_kind, "exited");
  assert.throws(
    () => parseRunResult(resultText.slice(0, -1) + ',"verified":true}'),
    (error) => error instanceof SdkError && error.code === "sdk.result.unknown-field",
  );
});

test("run uses exact argv without shell or ambient environment", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "proofbound-ts-sdk-"));
  try {
    const fake = path.join(root, "pbr");
    const plan = path.join(root, "plan;touch-injection");
    const receipt = path.join(root, "receipt.cbor");
    const cgroup = path.join(root, "cgroup");
    const script = [
      "#!/bin/sh",
      'test "$#" -eq 7 || exit 91',
      'test "$1" = run || exit 92',
      'test "$2" = --plan || exit 93',
      'test "$3" = "' + plan + '" || exit 94',
      'test "$4" = --receipt || exit 95',
      'test "$5" = "' + receipt + '" || exit 96',
      'test "$6" = --cgroup-root || exit 97',
      'test "$7" = "' + cgroup + '" || exit 98',
      'test "$EXACT" = yes || exit 99',
      'test -z "$PROOFBOUND_SDK_LEAK" || exit 100',
      "printf '%s\\n' '" + resultText + "'",
      "",
    ].join("\n");
    await writeFile(fake, script);
    await chmod(fake, 0o755);
    const old = process.env.PROOFBOUND_SDK_LEAK;
    process.env.PROOFBOUND_SDK_LEAK = "ambient";
    try {
      const result = await run({
        pbr: fake,
        plan,
        receipt,
        cgroupRoot: cgroup,
        environment: { EXACT: "yes" },
      });
      assert.equal(result.outcome_detail, 0);
    } finally {
      if (old === undefined) delete process.env.PROOFBOUND_SDK_LEAK;
      else process.env.PROOFBOUND_SDK_LEAK = old;
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("run kills oversized output", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "proofbound-ts-bound-"));
  try {
    const fake = path.join(root, "pbr");
    await writeFile(fake, "#!/bin/sh\nprintf '%0100d' 0\n");
    await chmod(fake, 0o755);
    await assert.rejects(
      run({
        pbr: fake,
        plan: path.join(root, "plan"),
        receipt: path.join(root, "receipt"),
        cgroupRoot: path.join(root, "cgroup"),
        environment: {},
        maxOutputBytes: 16,
      }),
      (error) => error instanceof SdkError && error.code === "sdk.process.output-bound",
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

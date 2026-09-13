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
    () => buildPlan({ ...goldenPlan(), network: "deny" }),
    (error) => error instanceof SdkError && error.code === "sdk.plan.unknown-field",
  );
  assert.throws(
    () => buildPlan({ ...goldenPlan(), memory_bytes: 65_537 }),
    (error) => error instanceof SdkError && error.code === "sdk.plan.limit-not-quantized",
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

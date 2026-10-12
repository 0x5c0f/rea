import { mkdir, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { expect } from "vitest";
import { TextReader, Uint8ArrayWriter, ZipWriter } from "@zip.js/zip.js";

import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { cliTest } from "../../support/cli/cliFixture.js";

import { analysisViewLayoutEvidence } from "../../fixtures/analysisView.js";
import { createEvidence, parseEvidence } from "../../../src/domain/evidence.js";
import { ghidraFunctionDossier } from "../../../src/domain/ghidraValues.fixture.js";
import { createEvidenceBundle } from "../../../src/domain/evidenceBundle.js";
import { inspectEvidenceBundle } from "../../../src/application/investigation/InspectEvidenceBundle.js";

cliTest(
  "projects portable artifact inventory after the original ZIP is removed",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-inventory-view-cli-");
    const archive = join(root, "fixture.zip");
    const writer = new ZipWriter(new Uint8ArrayWriter());
    await writer.add("main.js", new TextReader("console.log('portable');\n"));
    await writeFile(archive, await writer.close());
    const inspected = await cli.run({
      arguments: ["inspect-artifact", archive, "--json"],
    });
    expect(inspected.exitCode).toBe(0);
    const parent = parseEvidence(inspected.json);
    await unlink(archive);
    const request = join(root, "view.json");
    await writeFile(
      request,
      JSON.stringify({
        source: { kind: "inline", evidence: parent },
        view: {
          kind: "inventory",
          collection: "occurrences",
          logical_paths: ["main.js"],
        },
      }),
    );
    const projected = await cli.run({
      arguments: ["inspect-analysis-view", request, "--json"],
    });
    expect(projected.exitCode).toBe(0);
    expect(projected.json).toMatchObject({
      operation: "inspect_analysis_view",
      evidence_links: [parent.evidence_id],
      normalized_result: {
        parent_evidence_id: parent.evidence_id,
        kind: "inventory",
        source_complete: true,
        artifact: { path: archive, sha256: parent.subject?.digest.sha256 },
        items: [expect.objectContaining({ logical_path: "main.js" })],
        coverage: { total: 1, exhausted: true, next_offset: null },
      },
    });
  },
);

cliTest(
  "discovers native records from a complete portable bundle using the shared workflow",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-evidence-discovery-cli-");
    const parent = createEvidence(
      { path: "/fixtures/native.exe", format: "pe", sha256: "a".repeat(64) },
      { id: "ghidra", name: "Ghidra", version: "12.1.4" },
      {
        operation: "analyze_function",
        parameters: {},
        result: ghidraFunctionDossier(),
      },
    );
    const bundle = createEvidenceBundle([parent]);
    const path = join(root, "evidence.json");
    await writeFile(path, JSON.stringify(bundle));
    const options = {
      detail: "summary" as const,
      filters: { evidence_id: parent.evidence_id },
    };
    const result = await cli.run({
      arguments: [
        "inspect-evidence-bundle",
        JSON.stringify({ path, ...options }),
        "--json",
      ],
      environment: { HOME: root, XDG_CONFIG_HOME: root, XDG_CACHE_HOME: root },
    });
    expect(result.exitCode).toBe(0);
    const expected = inspectEvidenceBundle(bundle, options);
    if (!expected.ok) throw expected.error;
    expect(result.json).toEqual(expected.value);
    const complete = await cli.run({
      arguments: [
        "inspect-evidence-bundle",
        JSON.stringify({ path }),
        "--json",
      ],
      environment: { HOME: root, XDG_CONFIG_HOME: root, XDG_CACHE_HOME: root },
    });
    expect(complete.exitCode).toBe(0);
    expect(complete.json).toEqual(bundle);
  },
);
cliTest(
  "projects one section from a JSON file of inline layout Evidence",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-analysis-view-cli-");
    const parent = analysisViewLayoutEvidence();
    const request = {
      source: { kind: "inline", evidence: parent },
      view: {
        kind: "item",
        collection: "sections",
        selector: { name: ".data" },
      },
    };
    const input = join(root, "view.json");
    await mkdir(root, { recursive: true });
    await writeFile(input, JSON.stringify(request));
    const result = await cli.run({
      arguments: ["inspect-analysis-view", input, "--json"],
      environment: {
        HOME: root,
        XDG_CONFIG_HOME: root,
        XDG_CACHE_HOME: root,
      },
    });
    expect(result.exitCode).toBe(0);
    expect(result.json).toMatchObject({
      operation: "inspect_analysis_view",
      normalized_result: {
        kind: "item",
        parent_evidence_id: parent.evidence_id,
        item: { name: { display: ".data" } },
      },
    });
  },
);

cliTest(
  "projects native function pseudocode without requiring Ghidra",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-native-view-cli-");
    const parent = createEvidence(
      { path: "/fixtures/native.exe", format: "pe", sha256: "a".repeat(64) },
      { id: "ghidra", name: "Ghidra", version: "12.1.4" },
      {
        operation: "analyze_function",
        parameters: { address: "0x401000" },
        result: ghidraFunctionDossier(),
      },
    );
    const input = join(root, "native-view.json");
    await writeFile(
      input,
      JSON.stringify({
        source: { kind: "inline", evidence: parent },
        view: { kind: "native", facet: "pseudocode", offset: 0, limit: 12 },
      }),
    );
    const result = await cli.run({
      arguments: ["inspect-analysis-view", input, "--json"],
      environment: { HOME: root, XDG_CONFIG_HOME: root, XDG_CACHE_HOME: root },
    });
    expect(result.exitCode).toBe(0);
    expect(result.json).toMatchObject({
      operation: "inspect_analysis_view",
      normalized_result: {
        kind: "native",
        parent_evidence_id: parent.evidence_id,
        procedure_address: "0x401000",
        item: { text: "int fixture_", unit: "utf16-code-units" },
      },
      locations: [
        { kind: "artifact-path", path: "/fixtures/native.exe" },
        { kind: "address", address: "0x401000" },
      ],
    });
  },
);

cliTest("rejects malformed JSON before projection", async ({ cli }) => {
  const root = await createTestTempDirectory("rea-analysis-view-cli-bad-");
  const result = await cli.run({
    arguments: ["inspect-analysis-view", "{", "--json"],
    environment: {
      HOME: root,
      XDG_CONFIG_HOME: root,
      XDG_CACHE_HOME: root,
    },
  });
  expect(result.exitCode).toBe(1);
  expect(result.json).toMatchObject({
    code: "invalid_request",
    category: "invalid_input",
    details: { operation: "inspect-analysis-view" },
  });
});

cliTest("rejects a request that omits source", async ({ cli }) => {
  const root = await createTestTempDirectory("rea-analysis-view-cli-missing-");
  const input = join(root, "missing-source.json");
  await writeFile(input, JSON.stringify({ view: { kind: "summary" } }));
  const result = await cli.run({
    arguments: ["inspect-analysis-view", input, "--json"],
    environment: {
      HOME: root,
      XDG_CONFIG_HOME: root,
      XDG_CACHE_HOME: root,
    },
  });
  expect(result.exitCode).toBe(1);
  expect(result.json).toMatchObject({
    code: "invalid_request",
    category: "invalid_input",
    details: { operation: "inspect-analysis-view" },
  });
});

for (const [view, reason] of [
  [{ kind: "unknown-view" }, "invalid_value"],
  [{}, "missing_argument"],
] as const) {
  cliTest(
    `reports correction details for ${reason} view kind`,
    async ({ cli }) => {
      const root = await createTestTempDirectory("rea-view-variant-");
      const input = join(root, "view.json");
      await writeFile(
        input,
        JSON.stringify({
          source: {
            kind: "inline",
            evidence: analysisViewLayoutEvidence(),
          },
          view,
        }),
      );
      const result = await cli.run({
        arguments: ["inspect-analysis-view", input, "--json"],
        environment: {
          HOME: root,
          XDG_CONFIG_HOME: root,
          XDG_CACHE_HOME: root,
        },
      });
      expect(result.exitCode).toBe(1);
      expect(result.json).toMatchObject({
        code: "invalid_request",
        details: {
          issues: [
            {
              path: ["view", "kind"],
              reason,
              expected: expect.arrayContaining(["summary", "page"]),
            },
          ],
        },
      });
      expect(JSON.stringify(result.json)).not.toContain("unknown-view");
    },
  );
}

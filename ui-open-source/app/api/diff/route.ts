import { spawn } from "node:child_process";
import { resolve } from "node:path";

import { NextResponse } from "next/server";

import type { DiffPayload } from "@/lib/types";

interface RequestBody {
  repo_path?: string;
  base_ref?: string;
  head_ref?: string;
  baseline_path?: string | null;
  max_findings?: number | null;
  output_format?: "json";
}

interface RunResult {
  exitCode: number | null;
  stdout: string;
  stderr: string;
}

export async function POST(request: Request) {
  try {
    const body = (await request.json()) as RequestBody;
    const repoPath = (body.repo_path ?? ".").trim() || ".";
    const baseRef = (body.base_ref ?? "main").trim() || "main";
    const headRef = (body.head_ref ?? "HEAD").trim() || "HEAD";
    const baselinePath = body.baseline_path?.trim() || null;
    const maxFindings =
      body.max_findings === null || body.max_findings === undefined
        ? 50
        : Number(body.max_findings);

    if (!Number.isInteger(maxFindings) || maxFindings <= 0) {
      return NextResponse.json(
        { ok: false, error: "max_findings must be an integer >= 1." },
        { status: 400 },
      );
    }

    const runResult = await runCodevibesDiff({
      repoPath,
      baseRef,
      headRef,
      baselinePath,
      maxFindings,
    });

    if (runResult.exitCode !== 0) {
      const detail = runResult.stderr.trim() || runResult.stdout.trim() || "Unknown error.";
      return NextResponse.json(
        { ok: false, error: `Diff failed. Raw error: ${detail}` },
        { status: 500 },
      );
    }

    const { payload, warnings } = parseCliJson(runResult.stdout);
    return NextResponse.json({
      ok: true,
      data: { payload, warnings },
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unexpected server error.";
    return NextResponse.json({ ok: false, error: message }, { status: 500 });
  }
}

async function runCodevibesDiff(args: {
  repoPath: string;
  baseRef: string;
  headRef: string;
  baselinePath: string | null;
  maxFindings: number;
}): Promise<RunResult> {
  const repoRoot = process.env.CODEVIBES_ROOT
    ? resolve(process.env.CODEVIBES_ROOT)
    : resolve(process.cwd(), "..");
  const pythonBin = process.env.CODEVIBES_PYTHON ?? "python";

  const commandArgs: string[] = [
    "main.py",
    "diff",
    args.repoPath,
    "--format",
    "json",
    "--max-findings",
    String(args.maxFindings),
  ];
  if (args.baselinePath) {
    commandArgs.push("--baseline", args.baselinePath);
  } else {
    commandArgs.push("--base", args.baseRef, "--head", args.headRef);
  }

  return new Promise<RunResult>((resolveResult, rejectResult) => {
    const child = spawn(pythonBin, commandArgs, {
      cwd: repoRoot,
      env: { ...process.env, PYTHONIOENCODING: "utf-8" },
      windowsHide: true,
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString("utf-8");
    });
    child.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString("utf-8");
    });
    child.on("error", (error: Error) => {
      rejectResult(new Error(`Failed to launch Python: ${error.message}`));
    });
    child.on("close", (exitCode: number | null) => {
      resolveResult({ exitCode, stdout, stderr });
    });
  });
}

function parseCliJson(stdout: string): { payload: DiffPayload; warnings: string[] } {
  const text = stdout.trim();
  const firstBrace = text.indexOf("{");
  if (firstBrace < 0) {
    throw new Error("CodeVibes CLI did not return valid JSON output.");
  }
  const warningText = text.slice(0, firstBrace).trim();
  const jsonText = text.slice(firstBrace);

  let payload: DiffPayload;
  try {
    payload = JSON.parse(jsonText) as DiffPayload;
  } catch (error) {
    const detail = error instanceof Error ? error.message : "Invalid JSON.";
    throw new Error(`Failed to parse diff payload: ${detail}`);
  }

  const warnings = warningText
    ? warningText
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter(Boolean)
        .map((line) => line.replace(/^Warning:\s*/i, ""))
    : [];

  return { payload, warnings };
}


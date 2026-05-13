import { spawn } from "node:child_process";

import { NextResponse } from "next/server";

import {
  getCommandTimeoutMs,
  getPythonBin,
  getRepoRoot,
  guardApiRequest,
  resolveOptionalLocalPath,
  resolveProjectTarget,
  tryAcquireExecutionSlot,
} from "@/lib/security";
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
  timedOut: boolean;
}

export async function POST(request: Request) {
  const repoRoot = getRepoRoot();
  const guard = guardApiRequest(request, "diff");
  if (!guard.ok) {
    return errorResponse(guard.status, guard.error, guard.headers);
  }

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
      return errorResponse(400, "max_findings must be an integer >= 1.");
    }

    const safeRepoPath = resolveProjectTarget(repoPath, { repoRoot, field: "repo_path" });
    if (!safeRepoPath.ok) {
      return errorResponse(safeRepoPath.status, safeRepoPath.error, safeRepoPath.headers);
    }

    const safeBaselinePath = resolveOptionalLocalPath(baselinePath, {
      repoRoot,
      field: "baseline_path",
    });
    if (!safeBaselinePath.ok) {
      return errorResponse(safeBaselinePath.status, safeBaselinePath.error, safeBaselinePath.headers);
    }

    const slot = tryAcquireExecutionSlot();
    if (!slot.ok) {
      return errorResponse(slot.status, slot.error, slot.headers);
    }

    try {
      const runResult = await runCodevibesDiff({
        repoPath: safeRepoPath.value,
        baseRef,
        headRef,
        baselinePath: safeBaselinePath.value,
        maxFindings,
        repoRoot,
      });

      if (runResult.timedOut) {
        return errorResponse(504, "Diff timed out. Please narrow scope and retry.");
      }

      if (runResult.exitCode !== 0) {
        const detail = runResult.stderr.trim() || runResult.stdout.trim() || "Unknown error.";
        return errorResponse(500, `Diff failed. Raw error: ${detail}`);
      }

      const { payload, warnings } = parseCliJson(runResult.stdout);
      return NextResponse.json({
        ok: true,
        data: { payload, warnings },
      });
    } finally {
      slot.release();
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unexpected server error.";
    return errorResponse(500, message);
  }
}

async function runCodevibesDiff(args: {
  repoPath: string;
  baseRef: string;
  headRef: string;
  baselinePath: string | null;
  maxFindings: number;
  repoRoot: string;
}): Promise<RunResult> {
  const pythonBin = getPythonBin();
  const timeoutMs = getCommandTimeoutMs("diff");

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
      cwd: args.repoRoot,
      env: { ...process.env, PYTHONIOENCODING: "utf-8" },
      windowsHide: true,
    });
    let timedOut = false;
    let stdout = "";
    let stderr = "";
    const timeoutHandle = setTimeout(() => {
      timedOut = true;
      child.kill();
    }, timeoutMs);

    child.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString("utf-8");
    });
    child.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString("utf-8");
    });
    child.on("error", (error: Error) => {
      clearTimeout(timeoutHandle);
      rejectResult(new Error(`Failed to launch Python: ${error.message}`));
    });
    child.on("close", (exitCode: number | null) => {
      clearTimeout(timeoutHandle);
      resolveResult({ exitCode, stdout, stderr, timedOut });
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

function errorResponse(status: number, error: string, headers?: Record<string, string>) {
  return NextResponse.json(
    { ok: false, error },
    {
      status,
      headers,
    },
  );
}

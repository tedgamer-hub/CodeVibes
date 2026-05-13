import { spawn } from "node:child_process";

import { NextResponse } from "next/server";

import {
  getCommandTimeoutMs,
  getPythonBin,
  getRepoRoot,
  guardApiRequest,
  resolveProjectTarget,
  tryAcquireExecutionSlot,
} from "@/lib/security";
import type { ScanPayload } from "@/lib/types";

interface RequestBody {
  target?: string;
  top_files?: number;
  max_findings?: number | null;
  roast_mode?: boolean;
}

interface RunResult {
  exitCode: number | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
}

export async function POST(request: Request) {
  const repoRoot = getRepoRoot();
  const guard = guardApiRequest(request, "scan");
  if (!guard.ok) {
    return errorResponse(guard.status, guard.error, guard.headers);
  }

  try {
    const body = (await request.json()) as RequestBody;
    const target = (body.target ?? "").trim();
    const topFiles = Number.isInteger(body.top_files) ? Number(body.top_files) : 5;
    const maxFindings =
      body.max_findings === null || body.max_findings === undefined
        ? null
        : Number(body.max_findings);
    const roastMode = Boolean(body.roast_mode);

    if (!target) {
      return errorResponse(400, "Project path or GitHub URL is required.");
    }
    if (!Number.isInteger(topFiles) || topFiles <= 0) {
      return errorResponse(400, "top_files must be an integer >= 1.");
    }
    if (
      maxFindings !== null &&
      (!Number.isInteger(maxFindings) || Number(maxFindings) <= 0)
    ) {
      return errorResponse(400, "max_findings must be null or an integer >= 1.");
    }

    const safeTarget = resolveProjectTarget(target, { repoRoot, field: "target" });
    if (!safeTarget.ok) {
      return errorResponse(safeTarget.status, safeTarget.error, safeTarget.headers);
    }

    const slot = tryAcquireExecutionSlot();
    if (!slot.ok) {
      return errorResponse(slot.status, slot.error, slot.headers);
    }

    try {
      const runResult = await runCodevibesScan({
        target: safeTarget.value,
        topFiles,
        maxFindings,
        roastMode,
        repoRoot,
      });

      if (runResult.timedOut) {
        return errorResponse(504, "Scan timed out. Please narrow scope and retry.");
      }

      if (runResult.exitCode !== 0) {
        const detail = runResult.stderr.trim() || runResult.stdout.trim() || "Unknown error.";
        return errorResponse(500, formatFriendlyFailure(detail, target));
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

async function runCodevibesScan(args: {
  target: string;
  topFiles: number;
  maxFindings: number | null;
  roastMode: boolean;
  repoRoot: string;
}): Promise<RunResult> {
  const pythonBin = getPythonBin();
  const timeoutMs = getCommandTimeoutMs("scan");

  const commandArgs: string[] = [
    "main.py",
    "scan",
    args.target,
    "--format",
    "json",
    "--top-files",
    String(args.topFiles),
  ];
  if (args.maxFindings !== null) {
    commandArgs.push("--max-findings", String(args.maxFindings));
  }
  if (args.roastMode) {
    commandArgs.push("--roast");
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

function parseCliJson(stdout: string): { payload: ScanPayload; warnings: string[] } {
  const text = stdout.trim();
  const firstBrace = text.indexOf("{");
  if (firstBrace < 0) {
    throw new Error("CodeVibes CLI did not return valid JSON output.");
  }
  const warningText = text.slice(0, firstBrace).trim();
  const jsonText = text.slice(firstBrace);

  let payload: ScanPayload;
  try {
    payload = JSON.parse(jsonText) as ScanPayload;
  } catch (error) {
    const detail = error instanceof Error ? error.message : "Invalid JSON.";
    throw new Error(`Failed to parse scan payload: ${detail}`);
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

function formatFriendlyFailure(detail: string, target: string): string {
  const text = detail.trim();
  const lower = text.toLowerCase();
  const githubTarget = /^https?:\/\/github\.com\//i.test(target);
  if (githubTarget) {
    if (
      lower.includes("port 443") ||
      lower.includes("could not connect to server") ||
      lower.includes("connection was reset") ||
      lower.includes("recv failure")
    ) {
      return [
        "Failed to reach GitHub over HTTPS (github.com:443).",
        "Please check terminal network access (proxy/VPN/firewall) and retry.",
        `Raw error: ${text}`,
      ].join(" ");
    }
    if (lower.includes("could not resolve host") || lower.includes("name or service not known")) {
      return [
        "Failed to resolve github.com DNS.",
        "Please check DNS/proxy settings and retry.",
        `Raw error: ${text}`,
      ].join(" ");
    }
    if (lower.includes("repository not found") || lower.includes("not found")) {
      return [
        "GitHub repository was not found or is not accessible.",
        "Please verify owner/repo spelling and permissions.",
        `Raw error: ${text}`,
      ].join(" ");
    }
  }

  return `CodeVibes scan failed. Raw error: ${text}`;
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

import { spawn } from "node:child_process";
import { resolve } from "node:path";

import { NextResponse } from "next/server";

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
}

export async function POST(request: Request) {
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
      return NextResponse.json(
        { ok: false, error: "Project path or GitHub URL is required." },
        { status: 400 },
      );
    }
    if (!Number.isInteger(topFiles) || topFiles <= 0) {
      return NextResponse.json(
        { ok: false, error: "top_files must be an integer >= 1." },
        { status: 400 },
      );
    }
    if (
      maxFindings !== null &&
      (!Number.isInteger(maxFindings) || Number(maxFindings) <= 0)
    ) {
      return NextResponse.json(
        { ok: false, error: "max_findings must be null or an integer >= 1." },
        { status: 400 },
      );
    }

    const runResult = await runCodevibesScan({
      target,
      topFiles,
      maxFindings,
      roastMode,
    });

    if (runResult.exitCode !== 0) {
      const detail = runResult.stderr.trim() || runResult.stdout.trim() || "Unknown error.";
      return NextResponse.json(
        {
          ok: false,
          error: formatFriendlyFailure(detail, target),
        },
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

async function runCodevibesScan(args: {
  target: string;
  topFiles: number;
  maxFindings: number | null;
  roastMode: boolean;
}): Promise<RunResult> {
  const repoRoot = process.env.CODEVIBES_ROOT
    ? resolve(process.env.CODEVIBES_ROOT)
    : resolve(process.cwd(), "..");
  const pythonBin = process.env.CODEVIBES_PYTHON ?? "python";

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


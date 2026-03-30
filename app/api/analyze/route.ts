import { spawn } from "node:child_process";
import { resolve } from "node:path";

import { NextResponse } from "next/server";

import type { JsonScanPayload } from "@/lib/types";

interface AnalyzeRequestBody {
  target?: string;
  topFiles?: number;
  maxFindings?: number | null;
  roast?: boolean;
}

interface RunResult {
  exitCode: number | null;
  stdout: string;
  stderr: string;
}

export async function POST(req: Request) {
  try {
    const body = (await req.json()) as AnalyzeRequestBody;
    const target = (body.target ?? "").trim();
    const topFiles = Number.isInteger(body.topFiles) ? Number(body.topFiles) : 5;
    const maxFindings =
      body.maxFindings === null || body.maxFindings === undefined
        ? null
        : Number(body.maxFindings);
    const roast = Boolean(body.roast);

    if (!target) {
      return NextResponse.json(
        { ok: false, error: "Path or GitHub URL is required." },
        { status: 400 },
      );
    }
    if (!Number.isInteger(topFiles) || topFiles <= 0) {
      return NextResponse.json(
        { ok: false, error: "topFiles must be an integer greater than 0." },
        { status: 400 },
      );
    }
    if (
      maxFindings !== null &&
      (!Number.isInteger(maxFindings) || Number(maxFindings) <= 0)
    ) {
      return NextResponse.json(
        { ok: false, error: "maxFindings must be null or an integer greater than 0." },
        { status: 400 },
      );
    }

    const runResult = await runCodevibesScan({
      target,
      topFiles,
      maxFindings,
      roast,
    });

    if (runResult.exitCode !== 0) {
      const detail = runResult.stderr.trim() || runResult.stdout.trim() || "Unknown error.";
      return NextResponse.json(
        { ok: false, error: `CodeVibes scan failed: ${detail}` },
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

async function runCodevibesScan(params: {
  target: string;
  topFiles: number;
  maxFindings: number | null;
  roast: boolean;
}): Promise<RunResult> {
  const repoRoot = process.env.CODEVIBES_ROOT
    ? resolve(process.env.CODEVIBES_ROOT)
    : resolve(process.cwd(), "..");
  const pythonBin = process.env.CODEVIBES_PYTHON ?? "python";

  const args: string[] = [
    "main.py",
    "scan",
    params.target,
    "--format",
    "json",
    "--top-files",
    String(params.topFiles),
  ];
  if (params.maxFindings !== null) {
    args.push("--max-findings", String(params.maxFindings));
  }
  if (params.roast) {
    args.push("--roast");
  }

  return new Promise<RunResult>((resolveResult, rejectResult) => {
    const child = spawn(pythonBin, args, {
      cwd: repoRoot,
      env: process.env,
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

function parseCliJson(stdout: string): {
  payload: JsonScanPayload;
  warnings: string[];
} {
  const text = stdout.trim();
  const firstBrace = text.indexOf("{");
  if (firstBrace < 0) {
    throw new Error("CLI did not return JSON payload.");
  }

  const preamble = text.slice(0, firstBrace).trim();
  const jsonText = text.slice(firstBrace);
  let payload: JsonScanPayload;
  try {
    payload = JSON.parse(jsonText) as JsonScanPayload;
  } catch (error) {
    const detail = error instanceof Error ? error.message : "Invalid JSON.";
    throw new Error(`Unable to parse CodeVibes JSON output: ${detail}`);
  }

  const warnings = preamble
    ? preamble
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter(Boolean)
        .map((line) => line.replace(/^Warning:\s*/i, ""))
    : [];

  return { payload, warnings };
}


"use server";

// ════════════════════════════════════════════════════════════════════
//  WhipSite · live VPS metrics
//  Reads the host resource usage of the box running the panel so the
//  dashboard can show whether the server is behaving. Admin-only.
//  Inside Docker on Linux, os.* / /proc reflect the host VPS values;
//  disk reflects the container root fs (overlay) unless the host volume
//  is mounted at /.
// ════════════════════════════════════════════════════════════════════

import os from "os";
import { statfs, readFile } from "fs/promises";
import { requireAdmin } from "@/lib/server/auth";
import type { VpsMetrics } from "@/lib/types";

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

function cpuSnapshot() {
  let idle = 0;
  let total = 0;
  for (const c of os.cpus()) {
    for (const v of Object.values(c.times)) total += v;
    idle += c.times.idle;
  }
  return { idle, total };
}

// On Linux, MemAvailable is a far better "used" estimate than freemem
// (which excludes reclaimable page cache and overstates usage).
async function readMemAvailable(): Promise<number | null> {
  try {
    const txt = await readFile("/proc/meminfo", "utf8");
    const m = txt.match(/^MemAvailable:\s+(\d+)\s+kB/m);
    return m ? Number(m[1]) * 1024 : null;
  } catch {
    return null;
  }
}

export async function getSystemMetrics(): Promise<VpsMetrics> {
  await requireAdmin();

  // CPU%: delta of busy/total ticks over a short sampling window.
  const a = cpuSnapshot();
  await sleep(200);
  const b = cpuSnapshot();
  const idleDelta = b.idle - a.idle;
  const totalDelta = b.total - a.total;
  const cpuUsage =
    totalDelta > 0 ? Math.min(100, Math.max(0, Math.round((1 - idleDelta / totalDelta) * 100))) : 0;

  const totalMem = os.totalmem();
  const available = await readMemAvailable();
  const freeMem = available ?? os.freemem();
  const usedMem = Math.max(0, totalMem - freeMem);
  const memUsage = totalMem > 0 ? Math.round((usedMem / totalMem) * 100) : 0;

  let disk: VpsMetrics["disk"] = null;
  try {
    const st = await statfs(process.platform === "win32" ? process.cwd() : "/");
    const totalDisk = st.blocks * st.bsize;
    const freeDisk = st.bavail * st.bsize;
    const usedDisk = Math.max(0, totalDisk - freeDisk);
    if (totalDisk > 0) {
      disk = {
        usedBytes: usedDisk,
        totalBytes: totalDisk,
        usage: Math.round((usedDisk / totalDisk) * 100),
      };
    }
  } catch {
    disk = null;
  }

  return {
    cpu: { usage: cpuUsage, cores: os.cpus().length, load1: Number((os.loadavg()[0] ?? 0).toFixed(2)) },
    mem: { usedBytes: usedMem, totalBytes: totalMem, usage: memUsage },
    disk,
    uptimeSec: Math.round(os.uptime()),
    hostname: os.hostname(),
    capturedAt: new Date().toISOString(),
  };
}

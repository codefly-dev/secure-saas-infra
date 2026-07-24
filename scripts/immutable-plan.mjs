import { createHash } from "node:crypto";
import {
  closeSync,
  constants,
  fstatSync,
  mkdtempSync,
  openSync,
  readSync,
  rmSync,
  rmdirSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

export function openVerifiedPlan(file, expectedSha256) {
  const flags = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0);
  const fd = openSync(file, flags);
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile())
      throw new Error("Reviewed Pulumi plan is not a regular file.");
    const bytes = readFileDescriptor(fd, stat.size);
    const observed = createHash("sha256").update(bytes).digest("hex");
    if (observed !== expectedSha256) {
      throw new Error("Reviewed Pulumi plan changed after review.");
    }
    const directory = mkdtempSync(path.join(tmpdir(), "deus-reviewed-plan-"));
    const snapshot = path.join(directory, "plan");
    writeFileSync(snapshot, bytes, { flag: "wx", mode: 0o600 });
    const snapshotFd = openSync(snapshot, flags);
    unlinkSync(snapshot);
    rmdirSync(directory);
    closeSync(fd);
    return {
      fd: snapshotFd,
      childFileDescriptor: 3,
      childPath: "/dev/fd/3",
      sha256: observed,
    };
  } catch (error) {
    closeSync(fd);
    throw error;
  }
}

export function closeVerifiedPlan(binding) {
  closeSync(binding.fd);
}

function readFileDescriptor(fd, size) {
  const bytes = Buffer.allocUnsafe(size);
  let position = 0;
  while (position < size) {
    const count = readSync(fd, bytes, position, size - position, position);
    if (count === 0) break;
    position += count;
  }
  if (position !== size)
    throw new Error("Reviewed Pulumi plan could not be read completely.");
  return bytes;
}

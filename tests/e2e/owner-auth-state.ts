import path from "node:path";

export const defaultOwnerPassword = "correct horse battery staple";
export const ownerStorageStatePath = path.join(
  process.env.ENOKI_RELEASE_UI_EVIDENCE_DIR ??
    path.join(process.cwd(), ".scratch/e2e-data"),
  "owner-storage-state.json",
);

import type {
  OwnerSessionRecord,
  OwnerSessionRepository,
} from "./owner-session-repository.js";

export function createMemoryOwnerSessionRepository(): OwnerSessionRepository {
  const sessions = new Map<string, OwnerSessionRecord>();

  return {
    clear() {
      const removed = [...sessions.values()];
      sessions.clear();
      return removed;
    },
    deleteByTokenDigest(tokenDigest) {
      return sessions.delete(tokenDigest);
    },
    findByTokenDigest(tokenDigest) {
      return sessions.get(tokenDigest) ?? null;
    },
    list() {
      return [...sessions.values()];
    },
    save(session) {
      sessions.set(session.tokenDigest, { ...session });
    },
  };
}

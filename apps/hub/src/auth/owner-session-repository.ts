export type OwnerSessionRecord = Readonly<{
  createdAtMs: number;
  expiresAtMs: number;
  sequence: number;
  tokenDigest: string;
}>;

export type OwnerSessionRepository = {
  clear: () => readonly OwnerSessionRecord[];
  deleteByTokenDigest: (tokenDigest: string) => boolean;
  findByTokenDigest: (tokenDigest: string) => OwnerSessionRecord | null;
  list: () => readonly OwnerSessionRecord[];
  save: (session: OwnerSessionRecord) => void;
};

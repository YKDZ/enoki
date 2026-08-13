import { createMemoryOwnerSessionRepository } from "../src/auth/memory-owner-session-repository";
import { ownerSessionRepositoryContract } from "./owner-session-repository-contract";

ownerSessionRepositoryContract(
  "in-memory OwnerSessionRepository authentication contract",
  createMemoryOwnerSessionRepository,
);

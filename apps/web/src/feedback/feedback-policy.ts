export type FeedbackAction =
  | { hostId: number; kind: "recover-host-enrollment" }
  | { hostId: number; kind: "retry-host-enrollment" }
  | { kind: "none" };

export type FeedbackDecision =
  | {
      action?: FeedbackAction;
      aggregateKey: string;
      deduplicationKey: string;
      kind: "display";
      level: "error" | "info" | "success" | "warning";
      title: string;
      description?: string;
    }
  | { kind: "suppress" };

export function display(
  aggregateKey: string,
  level: Extract<FeedbackDecision, { kind: "display" }>["level"],
  title: string,
  options: {
    action?: FeedbackAction;
    deduplicationKey?: string;
    description?: string;
  } = {},
): FeedbackDecision {
  return {
    aggregateKey,
    deduplicationKey: options.deduplicationKey ?? aggregateKey,
    kind: "display",
    level,
    title,
    ...(options.description ? { description: options.description } : {}),
    ...(options.action ? { action: options.action } : {}),
  };
}

type Clearable = { clear(): void };

export function clearAuthenticatedFeedbackState(input: {
  feedback: Clearable;
  monitor: Clearable;
}) {
  input.monitor.clear();
  input.feedback.clear();
}

import type { InjectionKey } from "vue";

import type { WebFeedbackCoordinator } from "./web-feedback-coordinator";

export const webFeedbackKey: InjectionKey<WebFeedbackCoordinator> =
  Symbol("web-feedback");

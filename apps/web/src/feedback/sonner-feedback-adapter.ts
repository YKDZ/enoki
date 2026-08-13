import { toast } from "vue-sonner";

import "vue-sonner/style.css";

import type {
  FeedbackPresentation,
  WebFeedbackDelivery,
} from "./web-feedback-coordinator";

export { Toaster } from "vue-sonner";

export function createSonnerFeedbackDelivery(): WebFeedbackDelivery {
  return {
    deliver(presentation) {
      const options = {
        ...(presentation.action ? { action: presentation.action } : {}),
        ...(presentation.description
          ? { description: presentation.description }
          : {}),
      };
      switch (presentation.level) {
        case "error":
          toast.error(presentation.title, options);
          return;
        case "info":
          toast.info(presentation.title, options);
          return;
        case "success":
          toast.success(presentation.title, options);
          return;
        case "warning":
          toast.warning(presentation.title, options);
      }
    },
  };
}

export type { FeedbackPresentation };

import { renderToString } from "@vue/server-renderer";
import { describe, expect, it } from "vitest";
import { createSSRApp } from "vue";

import SparklineChart from "./SparklineChart.vue";

describe("SparklineChart", () => {
  it("keeps the decorative chart out of the accessibility tree", async () => {
    const html = await renderSparkline([
      [0, 25],
      [60_000, 75],
    ]);

    expect(html).toContain('aria-hidden="true"');
    expect(html).toContain('focusable="false"');
  });

  it("renders all sixty observed points through the production component defaults", async () => {
    const points = Array.from({ length: 60 }, (_, index) => [
      index * 1_000,
      index % 2 === 0 ? 5 : 95,
    ]) as Array<[number, number]>;
    const html = await renderSparkline(points);
    const renderedPoints = /<polyline points="([^"]+)"/.exec(html)?.[1];

    expect(renderedPoints?.split(" ")).toHaveLength(60);
  });

  it("keeps its layout shell without drawing a data line when no points exist", async () => {
    const html = await renderSparkline([]);

    expect(html).toContain('class="bg-background h-24 w-full border"');
    expect(html).toContain("<path");
    expect(html).not.toContain("<polyline");
  });
});

function renderSparkline(points: Array<[number, number]>) {
  return renderToString(
    createSSRApp(SparklineChart, {
      points,
      windowEndMs: 60_000,
      windowStartMs: 0,
    }),
  );
}

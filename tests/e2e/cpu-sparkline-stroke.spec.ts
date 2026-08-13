import { type Browser, type Locator } from "@playwright/test";

import { createLayoutLabFixture } from "../../apps/web/src/lib/layout-lab-fixtures";
import { expect, monitorSecurityConsole, test } from "./security-console";

const sparklineShapes = [
  { coreName: "cpu0", shape: "horizontal" },
  { coreName: "cpu1", shape: "spike" },
  { coreName: "cpu2", shape: "zigzag" },
] as const;

test("CPU core sparklines keep one visible screen-space stroke weight", async ({
  browser,
}) => {
  const targetStrokeWidthCssPx = 1.8;
  const absoluteToleranceCssPx = 0.7;
  const globalSpreadToleranceCssPx = 0.8;
  const measurements: Array<{
    deviceScaleFactor: number;
    shape: "horizontal" | "spike" | "zigzag";
    strokeWidthCssPx: number;
    viewportWidth: number;
  }> = [];

  for (const deviceScaleFactor of [1, 2]) {
    for (const width of [375, 768, 1024, 1440, 1920]) {
      const context = await browser.newContext({
        deviceScaleFactor,
        viewport: { height: 900, width },
      });
      try {
        const page = await context.newPage();
        const assertNoUnexpectedSecurityConsole = monitorSecurityConsole(page);
        await page.goto("/layout-lab?scenario=sparse", {
          waitUntil: "domcontentloaded",
        });

        const widths = await Promise.all(
          sparklineShapes.map(({ coreName }) =>
            visibleStrokeWidth(
              page.locator(
                `[data-panel-id="cpu"] [data-core-name="${coreName}"] polyline`,
              ),
            ),
          ),
        );

        for (const [index, { shape }] of sparklineShapes.entries()) {
          measurements.push({
            deviceScaleFactor,
            shape,
            strokeWidthCssPx: widths[index]!,
            viewportWidth: width,
          });
        }
        assertNoUnexpectedSecurityConsole();
      } finally {
        await context.close();
      }
    }
  }

  expect(measurements).toHaveLength(30);
  for (const measurement of measurements) {
    const message = `${measurement.shape}, ${measurement.viewportWidth}px at ${measurement.deviceScaleFactor}x: ${measurement.strokeWidthCssPx} CSS px`;
    expect(
      Math.abs(measurement.strokeWidthCssPx - targetStrokeWidthCssPx),
      message,
    ).toBeLessThanOrEqual(absoluteToleranceCssPx);
  }

  const allStrokeWidths = measurements.map(
    (measurement) => measurement.strokeWidthCssPx,
  );
  expect(
    Math.max(...allStrokeWidths) - Math.min(...allStrokeWidths),
    measurements
      .map(
        (measurement) =>
          `${measurement.shape} ${measurement.viewportWidth}px@${measurement.deviceScaleFactor}x=${measurement.strokeWidthCssPx}`,
      )
      .join(", "),
  ).toBeLessThanOrEqual(globalSpreadToleranceCssPx);
});

test("dense 60-point CPU sparklines keep fixed screen-space strokes", async ({
  browser,
}) => {
  const fixture = createLayoutLabFixture("dense");
  expect(fixture.samples).toHaveLength(60);
  expect(fixture.chartData.cpu.cores).toHaveLength(24);
  for (const core of fixture.chartData.cpu.cores) {
    expect(core.points, core.name).toHaveLength(60);
  }

  const measurements = await measureDenseSparklineStrokes(browser);
  expect(measurements).toHaveLength(18);
  for (const measurement of measurements) {
    const message = `${measurement.coreName}, ${measurement.viewportWidth}px at ${measurement.deviceScaleFactor}x: ${measurement.strokeWidthCssPx} CSS px`;
    expect(measurement.renderedPointCount, message).toBeGreaterThanOrEqual(60);
    expect(
      Math.abs(measurement.strokeWidthCssPx - 1.8),
      message,
    ).toBeLessThanOrEqual(0.7);
  }

  const widths = measurements.map(
    (measurement) => measurement.strokeWidthCssPx,
  );
  expect(
    Math.max(...widths) - Math.min(...widths),
    measurements
      .map(
        (measurement) =>
          `${measurement.coreName} ${measurement.viewportWidth}px@${measurement.deviceScaleFactor}x=${measurement.strokeWidthCssPx}`,
      )
      .join(", "),
  ).toBeLessThanOrEqual(0.8);
});

async function measureDenseSparklineStrokes(browser: Browser) {
  const measurements: Array<{
    coreName: string;
    deviceScaleFactor: number;
    renderedPointCount: number;
    strokeWidthCssPx: number;
    viewportWidth: number;
  }> = [];

  for (const deviceScaleFactor of [1, 2]) {
    for (const viewportWidth of [375, 1024, 1920]) {
      const context = await browser.newContext({
        deviceScaleFactor,
        viewport: { height: 900, width: viewportWidth },
      });
      try {
        const page = await context.newPage();
        const assertNoUnexpectedSecurityConsole = monitorSecurityConsole(page);
        await page.goto("/layout-lab?scenario=dense", {
          waitUntil: "domcontentloaded",
        });

        for (const coreName of ["cpu0", "cpu11", "cpu23"]) {
          const line = page.locator(
            `[data-panel-id="cpu"] [data-core-name="${coreName}"] polyline`,
          );
          measurements.push({
            coreName,
            deviceScaleFactor,
            renderedPointCount: await line
              .first()
              .evaluate(
                (element) => (element as SVGPolylineElement).points.length,
              ),
            strokeWidthCssPx: await visibleStrokeWidth(line),
            viewportWidth,
          });
        }
        assertNoUnexpectedSecurityConsole();
      } finally {
        await context.close();
      }
    }
  }

  return measurements;
}

async function visibleStrokeWidth(line: Locator) {
  const target = line.first();
  await target.scrollIntoViewIfNeeded();

  return await target.evaluate((element) => {
    const polyline = element as SVGPolylineElement;
    const matrix = polyline.getScreenCTM();
    if (!matrix) {
      throw new Error("Sparkline has no screen transform.");
    }

    const points = Array.from(polyline.points, ({ x, y }) => ({ x, y }));
    const segment = points
      .slice(0, -1)
      .map((from, index) => ({ from, to: points[index + 1]! }))
      .map(({ from, to }) => {
        const start = new DOMPoint(from.x, from.y).matrixTransform(matrix);
        const end = new DOMPoint(to.x, to.y).matrixTransform(matrix);
        return {
          end,
          length: Math.hypot(end.x - start.x, end.y - start.y),
          start,
        };
      })
      .sort((left, right) => right.length - left.length)[0];

    if (!segment || segment.length <= 0) {
      throw new Error("Sparkline has no measurable line segment.");
    }

    const midpoint = {
      x: (segment.start.x + segment.end.x) / 2,
      y: (segment.start.y + segment.end.y) / 2,
    };
    const normal = {
      x: -(segment.end.y - segment.start.y) / segment.length,
      y: (segment.end.x - segment.start.x) / segment.length,
    };
    const hitOffsets: number[] = [];

    for (let offset = -10; offset <= 10; offset += 0.1) {
      const hit = document.elementFromPoint(
        midpoint.x + normal.x * offset,
        midpoint.y + normal.y * offset,
      );
      if (hit === polyline) {
        hitOffsets.push(offset);
      }
    }

    if (hitOffsets.length === 0) {
      throw new Error("Sparkline is not painted at its visible midpoint.");
    }

    return Number(
      (Math.max(...hitOffsets) - Math.min(...hitOffsets) + 0.1).toFixed(1),
    );
  });
}

import { expect, test, type Page } from "@playwright/test";

const viewportCases = [
  { height: 900, width: 375 },
  { height: 900, width: 768 },
  { height: 900, width: 1024 },
  { height: 1000, width: 1440 },
  { height: 1080, width: 1920 },
] as const;

test.describe("卡槽布局实验室", () => {
  for (const viewport of viewportCases) {
    test(`密集数据在 ${viewport.width}px 下不溢出或重叠`, async ({ page }) => {
      await page.setViewportSize(viewport);
      await page.goto("/layout-lab?scenario=dense");

      await expect(
        page.getByRole("heading", { name: "卡槽布局实验室" }),
      ).toBeVisible();
      await expect(page.locator("[data-layout-card]")).toHaveCount(11);
      await expectNoHorizontalOverflow(page);
      await expectNoCardOverlap(page);
      await expectChartsHaveStableSize(page);
    });
  }

  test("稀疏数据也保持相同卡槽结构", async ({ page }) => {
    await page.setViewportSize({ height: 900, width: 1024 });
    await page.goto("/layout-lab?scenario=sparse");

    await expect(
      page.locator("[data-layout-section='production-slots']"),
    ).toBeVisible();
    await expect(page.locator("[data-panel-id]")).toHaveCount(4);
    await expectNoHorizontalOverflow(page);
    await expectNoCardOverlap(page);
  });

  test("折叠状态在首屏渲染前恢复", async ({ page }) => {
    await page.setViewportSize({ height: 900, width: 1280 });
    await page.addInitScript(() => {
      window.localStorage.setItem("enoki:host:9001:panel:cpu:collapsed", "1");
    });
    await page.goto("/layout-lab?scenario=dense");

    const cpuPanel = page.locator("[data-panel-id='cpu']");
    await expect(cpuPanel.getByRole("button", { name: "展开" })).toBeVisible();
    await expect(cpuPanel.getByText("CPU 型号")).toBeVisible();
    await expect(cpuPanel.getByText("CPU 0")).toHaveCount(0);
    await expectNoHorizontalOverflow(page);
    await expectNoCardOverlap(page);
  });
});

async function expectNoHorizontalOverflow(page: Page) {
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - window.innerWidth,
  );

  expect(overflow).toBeLessThanOrEqual(1);
}

async function expectNoCardOverlap(page: Page) {
  const overlaps = await page
    .locator("[data-layout-card]")
    .evaluateAll((cards) => {
      const rects = cards
        .map((card, index) => {
          const rect = card.getBoundingClientRect();
          return {
            bottom: rect.bottom,
            height: rect.height,
            index,
            left: rect.left,
            right: rect.right,
            top: rect.top,
            width: rect.width,
          };
        })
        .filter((rect) => rect.width > 0 && rect.height > 0);
      const errors: string[] = [];

      for (let leftIndex = 0; leftIndex < rects.length; leftIndex += 1) {
        for (
          let rightIndex = leftIndex + 1;
          rightIndex < rects.length;
          rightIndex += 1
        ) {
          const left = rects[leftIndex];
          const right = rects[rightIndex];
          const intersects =
            left.left < right.right - 1 &&
            left.right > right.left + 1 &&
            left.top < right.bottom - 1 &&
            left.bottom > right.top + 1;

          if (intersects) {
            errors.push(`${left.index}-${right.index}`);
          }
        }
      }

      return errors;
    });

  expect(overlaps).toEqual([]);
}

async function expectChartsHaveStableSize(page: Page) {
  const invalidCharts = await page
    .locator("[data-smoke-chart-title], [data-layout-chart]")
    .evaluateAll((charts) =>
      charts
        .map((chart, index) => {
          const rect = chart.getBoundingClientRect();
          return { height: rect.height, index, width: rect.width };
        })
        .filter((rect) => rect.width < 160 || rect.height < 180),
    );

  expect(invalidCharts).toEqual([]);
}

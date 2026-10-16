// T-5 T-37
import { test as base, expect } from "@playwright/test";

/** Playwright `test` that opens the kernel page and fails on any console error, page error or CSP violation. */
export const test = base.extend<{ pageErrors: string[] }>({
  pageErrors: [
    async ({ page }, use) => {
      const errors: string[] = [];
      page.on("console", (message) => {
        if (message.type() === "error") errors.push(message.text());
      });
      page.on("pageerror", (error) => {
        errors.push(error.message);
      });
      await page.goto("/");
      await page.waitForFunction(() => "workKernel" in window);
      await use(errors);
      expect(errors).toEqual([]);
    },
    { auto: true },
  ],
});

export { expect };

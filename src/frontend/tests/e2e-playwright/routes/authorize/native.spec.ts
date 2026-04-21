import { expect } from "@playwright/test";
import { II_URL } from "../../utils";
import { test } from "../../fixtures";

test("Shows an error for an unknown native authorization request", async ({
  page,
}) => {
  await page.goto(`${II_URL}/authorize?native_request_id=missing-request`);

  await expect(
    page.getByRole("heading", { level: 1, name: "Invalid request" }),
  ).toBeVisible();
  await expect(
    page.getByText(
      "It seems like an invalid authentication request was received.",
    ),
  ).toBeVisible();
});

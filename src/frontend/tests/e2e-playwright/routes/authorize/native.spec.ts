import { expect } from "@playwright/test";
import { II_URL } from "../../utils";
import { test } from "../../fixtures";

const invalidNativeAuthorizeUrls = [
  `${II_URL}/authorize?response_type=code&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback`,
  `${II_URL}/authorize?client_id=com.example.app`,
  `${II_URL}/authorize?response_type=code&client_id=com.example.app`,
];

for (const url of invalidNativeAuthorizeUrls) {
  test(`Shows an error for an invalid native authorization request: ${url}`, async ({
    page,
  }) => {
    await page.goto(url);

    await expect(
      page.getByRole("heading", { level: 1, name: "Invalid request" }),
    ).toBeVisible();
    await expect(
      page.getByText(
        "It seems like an invalid authentication request was received.",
      ),
    ).toBeVisible();
  });
}

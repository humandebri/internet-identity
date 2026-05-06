import { expect } from "@playwright/test";
import { II_URL } from "../../utils";
import { test } from "../../fixtures";

const backendConfigUrl =
  "http://internet_identity.local.localhost:8000/.config.did.bin";

test("Shows an error for an unknown native authorization request", async ({
  page,
}) => {
  const backendConfigResponse = page.waitForResponse(
    (response) => response.url() === backendConfigUrl,
  );

  await page.goto(`${II_URL}/authorize?native_request_id=missing-request`);

  expect((await backendConfigResponse).status()).toBe(200);
  await expect(
    page.getByRole("heading", { level: 1, name: "Invalid request" }),
  ).toBeVisible();
  await expect(
    page.getByText(
      "It seems like an invalid authentication request was received.",
    ),
  ).toBeVisible();
});

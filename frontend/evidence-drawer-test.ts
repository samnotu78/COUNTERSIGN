import { test, expect } from '@playwright/test';

const scenarios = [
  { id: 'valid', expectedVerdict: 'VERIFIED' },
  { id: 'tampered', expectedVerdict: 'UNVERIFIABLE' },
  { id: 'compromised_ai', expectedVerdict: 'UNVERIFIABLE' },
  { id: 'contradictory_claim', expectedVerdict: 'CONTRADICTS_POLICY' },
  { id: 'ungrounded_ai', expectedVerdict: 'UNVERIFIABLE' },
];

for (const scenario of scenarios) {
  test(`Scenario: ${scenario.id} → ${scenario.expectedVerdict}`, async ({ page }) => {
    await page.goto('http://localhost:5173');
    await page.waitForLoadState('networkidle');

    // Select scenario
    const scenarioCard = page.locator(`button:has-text("${scenario.id.toUpperCase()}")`).first();
    await scenarioCard.click();
    await expect(scenarioCard).toHaveAttribute('aria-pressed', 'true');

    // Click verify
    const verifyButton = page.locator('button:has-text("VERIFY SELECTED SCENARIO")');
    await verifyButton.click();

    // Wait for completion
    await page.waitForSelector(`text=${scenario.expectedVerdict}`, { timeout: 15000 });

    // Verify Evidence button appears
    const evidenceButton = page.locator('button:has-text("Evidence")');
    await expect(evidenceButton).toBeVisible();

    // Open Evidence Drawer
    await evidenceButton.click();

    // Wait for drawer to open
    await page.waitForSelector('text=Verification Evidence', { timeout: 5000 });

    // Verify all four tabs exist
    const tabs = ['Cryptographic', 'AI Interpretation', 'Policy', 'Metadata'];
    for (const tab of tabs) {
      await expect(page.locator(`button:has-text("${tab}")`)).toBeVisible();
    }

    // Test Cryptographic tab
    await page.locator('button:has-text("Cryptographic")').click();
    await expect(page.locator('text=Verified Fields')).toBeVisible();
    await expect(page.locator('text=Signed Values')).toBeVisible();
    await expect(page.locator('text=Verification Metadata')).toBeVisible();

    // Test AI Interpretation tab
    await page.locator('button:has-text("AI Interpretation")').click();
    await expect(page.locator('text=UNTRUSTED SENSOR OUTPUT')).toBeVisible();
    await expect(page.locator('text=Interpretation Status')).toBeVisible();
    await expect(page.locator('text=Extracted Claims')).toBeVisible();

    // Test Policy tab
    await page.locator('button:has-text("Policy")').click();
    await expect(page.locator('text=Policy Evaluation')).toBeVisible();
    await expect(page.locator('text=deterministic')).toBeVisible();

    // Test Metadata tab
    await page.locator('button:has-text("Metadata")').click();
    await expect(page.locator('text=Request Identity')).toBeVisible();
    await expect(page.locator('text=Backend Explanation')).toBeVisible();

    // Test Close button
    await page.locator('button[aria-label="Close evidence drawer"]').click();
    await expect(page.locator('text=Verification Evidence')).not.toBeVisible();

    // Reopen and test backdrop click
    await evidenceButton.click();
    await page.waitForSelector('text=Verification Evidence');
    await page.locator('div.fixed.inset-0.bg-black\\/50').click({ position: { x: 10, y: 10 } });
    await expect(page.locator('text=Verification Evidence')).not.toBeVisible();

    // Reopen and test Escape key
    await evidenceButton.click();
    await page.waitForSelector('text=Verification Evidence');
    await page.keyboard.press('Escape');
    await expect(page.locator('text=Verification Evidence')).not.toBeVisible();

    // Test Request ID copy button exists
    await evidenceButton.click();
    await page.waitForSelector('text=Verification Evidence');
    await page.locator('button:has-text("Metadata")').click();
    const copyButton = page.locator('button:has-text("Copy")').first();
    await expect(copyButton).toBeVisible();
  });
}

// Regression test: 375px mobile viewport
test('Mobile viewport 375px - no horizontal overflow', async ({ page }) => {
  await page.setViewportSize({ width: 375, height: 667 });
  await page.goto('http://localhost:5173');
  await page.waitForLoadState('networkidle');

  const bodyWidth = await page.evaluate(() => document.body.scrollWidth);
  expect(bodyWidth).toBeLessThanOrEqual(375);

  // Scenario selection still works
  await page.locator('button:has-text("VALID REQUEST")').click();
  await expect(page.locator('button:has-text("VALID REQUEST")')).toHaveAttribute('aria-pressed', 'true');
});

// Regression test: Reset behavior
test('Reset returns to IDLE state', async ({ page }) => {
  await page.goto('http://localhost:5173');
  await page.waitForLoadState('networkidle');

  await page.locator('button:has-text("VALID REQUEST")').click();
  await page.locator('button:has-text("VERIFY SELECTED SCENARIO")').click();
  await page.waitForSelector('text=VERIFIED', { timeout: 15000 });

  await page.locator('button:has-text("RESET")').click();
  await expect(page.locator('text=Awaiting Verification')).toBeVisible();
});

// Regression test: No console errors
test('No browser console errors', async ({ page }) => {
  const errors: string[] = [];
  page.on('console', msg => {
    if (msg.type() === 'error') errors.push(msg.text());
  });
  page.on('pageerror', error => {
    errors.push(error.message);
  });

  await page.goto('http://localhost:5173');
  await page.waitForLoadState('networkidle');

  await page.locator('button:has-text("VALID REQUEST")').click();
  await page.locator('button:has-text("VERIFY SELECTED SCENARIO")').click();
  await page.waitForSelector('text=VERIFIED', { timeout: 15000 });

  // Filter out expected errors (e.g., clipboard API in test environment)
  const relevantErrors = errors.filter(e => 
    !e.includes('clipboard') && 
    !e.includes('Clipboard') &&
    !e.includes('clipboard-read')
  );
  expect(relevantErrors).toHaveLength(0);
});
import test from "node:test";
import assert from "node:assert/strict";
import {
  flushPulumiMocks,
  installPulumiMocks,
  resourcesOfType,
} from "./helpers/pulumiMocks";

test("cost-controls stack creates per-tenant budgets and a cost anomaly subscription", async () => {
  const { resources } = await installPulumiMocks();
  const { createCostControls } = await import("../src/costControls");

  createCostControls({
    notificationEmails: ["finops@deus.example"],
    enableAnomalyDetection: true,
    anomalyMinImpactUsd: 100,
    tenantBudgets: [
      { tenantId: "tenant-a", monthlyLimitUsd: 1000, thresholdPercent: 80 },
      { tenantId: "tenant-b", monthlyLimitUsd: 500, thresholdPercent: 90 },
    ],
  });

  await flushPulumiMocks();

  const budgets = resourcesOfType(resources, "aws:budgets/budget:Budget");
  assert.equal(budgets.length, 2);
  assert.ok(
    budgets.every(
      (budget) =>
        budget.inputs.budgetType === "COST" &&
        budget.inputs.timeUnit === "MONTHLY",
    ),
  );
  assert.ok(
    budgets.every((budget) =>
      String(budget.inputs.costFilters[0].values[0]).includes(
        "user:TenantId$",
      ),
    ),
  );

  const monitor = resourcesOfType(
    resources,
    "aws:costexplorer/anomalyMonitor:AnomalyMonitor",
  )[0];
  assert.ok(monitor);

  const subscription = resourcesOfType(
    resources,
    "aws:costexplorer/anomalySubscription:AnomalySubscription",
  )[0];
  assert.ok(subscription);
  assert.equal(
    subscription.inputs.thresholdExpression.dimension.values[0],
    "100",
  );
});

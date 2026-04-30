import * as aws from "@pulumi/aws";
import * as pulumi from "@pulumi/pulumi";
import { CostControlsConfig, baseTags, named } from "./config";

export interface CostControlsResult {
  budgets: aws.budgets.Budget[];
  anomalyMonitor?: aws.costexplorer.AnomalyMonitor;
  anomalySubscription?: aws.costexplorer.AnomalySubscription;
}

export function createCostControls(
  config: CostControlsConfig,
): CostControlsResult {
  const budgets = config.tenantBudgets.map((entry, index) => {
    const subscriberArgs: aws.types.input.budgets.BudgetNotification = {
      comparisonOperator: "GREATER_THAN",
      threshold: entry.thresholdPercent,
      thresholdType: "PERCENTAGE",
      notificationType: "ACTUAL",
      subscriberEmailAddresses: config.notificationEmails,
    };

    return new aws.budgets.Budget(named(`tenant-budget-${index + 1}`), {
      name: named(`tenant-budget-${entry.tenantId}`),
      budgetType: "COST",
      timeUnit: "MONTHLY",
      limitAmount: entry.monthlyLimitUsd.toString(),
      limitUnit: "USD",
      costFilters: [
        {
          name: "TagKeyValue",
          values: [`user:TenantId$${entry.tenantId}`],
        },
      ],
      notifications: [subscriberArgs],
      tags: tag(`tenant-budget-${entry.tenantId}`, {
        EvidenceClass: "cost-control",
        TenantId: entry.tenantId,
      }),
    });
  });

  let anomalyMonitor: aws.costexplorer.AnomalyMonitor | undefined;
  let anomalySubscription: aws.costexplorer.AnomalySubscription | undefined;

  if (config.enableAnomalyDetection) {
    anomalyMonitor = new aws.costexplorer.AnomalyMonitor(
      named("cost-anomaly-monitor"),
      {
        name: named("cost-anomaly-monitor"),
        monitorType: "DIMENSIONAL",
        monitorDimension: "SERVICE",
        tags: tag("cost-anomaly-monitor", { EvidenceClass: "cost-control" }),
      },
    );

    anomalySubscription = new aws.costexplorer.AnomalySubscription(
      named("cost-anomaly-subscription"),
      {
        name: named("cost-anomaly-subscription"),
        frequency: "DAILY",
        monitorArnLists: [anomalyMonitor.arn],
        subscribers: config.notificationEmails.map((email) => ({
          type: "EMAIL",
          address: email,
        })),
        thresholdExpression: {
          dimension: {
            key: "ANOMALY_TOTAL_IMPACT_ABSOLUTE",
            matchOptions: ["GREATER_THAN_OR_EQUAL"],
            values: [String(config.anomalyMinImpactUsd)],
          },
        },
        tags: tag("cost-anomaly-subscription", {
          EvidenceClass: "cost-control",
        }),
      },
    );
  }

  return { budgets, anomalyMonitor, anomalySubscription };
}

function tag(name: string, extra: Record<string, string> = {}) {
  return {
    ...baseTags,
    Name: named(name),
    ...extra,
  };
}

export type AwsPolicyScalar = string | number | boolean;
export type AwsPolicyValue = AwsPolicyScalar | readonly AwsPolicyScalar[];

export interface AwsPolicyStatement {
  Sid: string;
  Effect: "Allow" | "Deny";
  Action: string | readonly string[];
  Resource?: string | readonly string[];
  Principal?: Readonly<Record<string, string | readonly string[]>>;
  Condition?: Readonly<
    Record<string, Readonly<Record<string, AwsPolicyValue>>>
  >;
}

export interface AwsPolicyDocument {
  Version: "2012-10-17";
  Statement: readonly AwsPolicyStatement[];
}

export function policyDocument(
  statements: readonly AwsPolicyStatement[],
): AwsPolicyDocument {
  return {
    Version: "2012-10-17",
    Statement: [...statements]
      .map(normalizeStatement)
      .sort((left, right) => left.Sid.localeCompare(right.Sid)),
  };
}

export function canonicalPolicyJson(document: AwsPolicyDocument): string {
  return JSON.stringify(sortObject(document));
}

function normalizeStatement(statement: AwsPolicyStatement): AwsPolicyStatement {
  return {
    ...statement,
    Action: sortedValue(statement.Action),
    ...(statement.Resource === undefined
      ? {}
      : { Resource: sortedValue(statement.Resource) }),
    ...(statement.Principal === undefined
      ? {}
      : {
          Principal: Object.fromEntries(
            Object.entries(statement.Principal)
              .sort(([left], [right]) => left.localeCompare(right))
              .map(([key, value]) => [key, sortedValue(value)]),
          ),
        }),
  };
}

function sortedValue(
  value: string | readonly string[],
): string | readonly string[] {
  return Array.isArray(value) ? [...value].sort() : (value as string);
}

function sortObject(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortObject);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, entry]) => [key, sortObject(entry)]),
    );
  }
  return value;
}

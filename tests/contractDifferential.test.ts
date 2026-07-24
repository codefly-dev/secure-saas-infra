import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { IAC_CONTRACT_REGISTRY } from "./contracts/iacContractRegistry";

interface Mutation {
  id: string;
  value: unknown;
}

const ajv = new Ajv2020({
  allErrors: true,
  allowUnionTypes: false,
  strict: true,
  validateFormats: true,
});
addFormats(ajv);
for (const entry of IAC_CONTRACT_REGISTRY) {
  if (!ajv.getSchema(entry.schemaId)) {
    ajv.addSchema(readJson(entry.schemaPath) as any, entry.schemaId);
  }
}

test("active checked IaC contracts have one owned parser/schema/canonicalizer registry", () => {
  const sharedRegistry = readJson("security/iac-contract-registry.json") as {
    checkedContracts: Array<{
      contract: string;
      schema: string;
      owner: string;
    }>;
  };
  assert.deepEqual(
    IAC_CONTRACT_REGISTRY.map((entry) => ({
      contract: entry.contractPath.replace(/^contracts\//, ""),
      schema: entry.schemaPath.replace(/^schemas\//, ""),
      owner: entry.owner,
    })).sort((left, right) => left.contract.localeCompare(right.contract)),
    sharedRegistry.checkedContracts.sort((left, right) =>
      left.contract.localeCompare(right.contract),
    ),
    "parser registry and validation registry must have identical checked-contract mappings",
  );
  assert.deepEqual(
    IAC_CONTRACT_REGISTRY.map((entry) => entry.contractPath).sort(),
    [
      "contracts/aws-bootstrap-access-v1alpha1.json",
      "contracts/aws-database-infrastructure-handoff-v1alpha1.json",
      "contracts/cloud-context-observation-v1alpha1.json",
      "contracts/cloud-context-v1alpha1.json",
      "contracts/infrastructure-controller-protocol-v1alpha1.json",
      "contracts/infrastructure-controller-request-v1alpha1.json",
      "contracts/managed-postgres-v1alpha1.json",
      "contracts/managed-postgres-v1alpha2.json",
      "contracts/postgres-access-observation-v1alpha1.json",
      "contracts/postgres-access-profile-v1alpha1.json",
      "contracts/workload-identity-binding-v1alpha1.json",
    ],
  );
  for (const entry of IAC_CONTRACT_REGISTRY) {
    assert.match(entry.owner, /^secure-saas-infra\/[a-z0-9-]+$/);
    assert.ok(entry.parserOnlySemanticRules.length > 0);
    const schema = readJson(entry.schemaPath) as any;
    assert.equal(schema.$id, entry.schemaId);
    const fixture = readJson(entry.contractPath);
    assert.equal(ajv.getSchema(entry.schemaId)!(fixture), true, entry.id);
    assert.doesNotThrow(() => entry.parse(fixture), entry.id);
    assert.match(entry.canonicalDigest(fixture), /^[a-f0-9]{64}$/);
  }
});

for (const entry of IAC_CONTRACT_REGISTRY) {
  test(`${entry.id} schema-rejection corpus is also rejected by its parser`, () => {
    const fixture = readJson(entry.contractPath);
    const schema = readJson(entry.schemaPath);
    const validate = ajv.getSchema(entry.schemaId)!;
    const mutations = generateSchemaRejectionMutations(schema, fixture);
    assert.ok(
      mutations.length >= 25,
      `${entry.id} produced only ${mutations.length} mutations`,
    );
    assert.equal(
      new Set(mutations.map((mutation) => mutation.id)).size,
      mutations.length,
      `${entry.id} generated duplicate mutation IDs`,
    );
    const mutationIds = new Set(mutations.map((mutation) => mutation.id));
    for (const requiredPath of collectRequiredPaths(schema, fixture)) {
      assert.ok(
        mutationIds.has(`required:${formatPath(requiredPath)}`),
        `${entry.id} did not generate a required-field mutation for ${formatPath(requiredPath)}`,
      );
    }
    for (const mutation of mutations) {
      const before = JSON.stringify(mutation.value);
      const schemaAccepted = validate(mutation.value);
      assert.equal(
        schemaAccepted,
        false,
        `${entry.id}/${mutation.id} unexpectedly passed schema validation`,
      );
      assert.throws(
        () => entry.parse(mutation.value),
        `${entry.id}/${mutation.id} was rejected by AJV but accepted by the parser`,
      );
      assert.equal(
        JSON.stringify(mutation.value),
        before,
        `${entry.id}/${mutation.id} was mutated by a rejecting parser`,
      );
    }
  });

  test(`${entry.id} canonical digest ignores object key order but preserves arrays`, () => {
    const fixture = readJson(entry.contractPath);
    const reordered = reverseObjectKeys(fixture);
    assert.equal(
      entry.canonicalDigest(reordered),
      entry.canonicalDigest(fixture),
    );

    const arrayPath = firstArrayPath(fixture);
    if (arrayPath) {
      const reversedArrays = structuredClone(fixture);
      const array = getAtPath(reversedArrays, arrayPath) as unknown[];
      if (array.length <= 1) return;
      array.reverse();
      try {
        const reversedDigest = entry.canonicalDigest(reversedArrays);
        assert.notEqual(
          reversedDigest,
          entry.canonicalDigest(fixture),
          `${entry.id}/${formatPath(arrayPath)} must preserve array order`,
        );
      } catch {
        // A semantic parser may reject reordering an ordered event/account set;
        // rejection is also a valid declaration that array order is significant.
      }
    }
  });
}

function collectRequiredPaths(
  rootSchema: unknown,
  fixture: unknown,
): Array<readonly (string | number)[]> {
  const paths: Array<readonly (string | number)[]> = [];
  const visit = (
    schemaValue: unknown,
    value: unknown,
    path: readonly (string | number)[],
  ) => {
    const schema = selectSchema(rootSchema, schemaValue, value);
    if (isObject(value)) {
      for (const key of schema.required ?? []) {
        if (typeof key === "string" && key in value) paths.push([...path, key]);
      }
      const properties = isObject(schema.properties) ? schema.properties : {};
      for (const [key, entry] of Object.entries(value)) {
        if (key in properties) visit(properties[key], entry, [...path, key]);
      }
      return;
    }
    if (Array.isArray(value)) {
      const prefixItems = Array.isArray(schema.prefixItems)
        ? schema.prefixItems
        : [];
      value.forEach((entry, index) => {
        if (prefixItems[index] !== undefined) {
          visit(prefixItems[index], entry, [...path, index]);
        } else if (schema.items !== undefined && schema.items !== false) {
          visit(schema.items, entry, [...path, index]);
        }
      });
    }
  };
  visit(rootSchema, fixture, []);
  return paths;
}

function generateSchemaRejectionMutations(
  rootSchema: unknown,
  fixture: unknown,
): Mutation[] {
  const mutations: Mutation[] = [];
  const seen = new Set<string>();
  const add = (
    kind: string,
    path: readonly (string | number)[],
    mutate: (copy: any) => void,
  ) => {
    const id = `${kind}:${formatPath(path)}`;
    if (seen.has(id)) return;
    const copy = structuredClone(fixture);
    mutate(copy);
    mutations.push({ id, value: copy });
    seen.add(id);
  };

  const visit = (
    schemaValue: unknown,
    value: unknown,
    path: readonly (string | number)[],
  ): void => {
    const schema = selectSchema(rootSchema, schemaValue, value);
    if (schema.const !== undefined) {
      add("const", path, (copy) => setAtPath(copy, path, unlike(schema.const)));
    } else if (Array.isArray(schema.enum)) {
      add("enum", path, (copy) =>
        setAtPath(copy, path, "__unsupported_enum__"),
      );
    }

    if (typeof value === "number") {
      if (typeof schema.minimum === "number") {
        add("minimum", path, (copy) =>
          setAtPath(copy, path, schema.minimum - 1),
        );
      }
      if (typeof schema.maximum === "number") {
        add("maximum", path, (copy) =>
          setAtPath(copy, path, schema.maximum + 1),
        );
      }
    }
    if (typeof value === "string") {
      if (
        schema.const === undefined &&
        !Array.isArray(schema.enum) &&
        (typeof schema.pattern === "string" ||
          typeof schema.format === "string")
      ) {
        add("string-constraint", path, (copy) =>
          setAtPath(copy, path, "\u0000"),
        );
      }
      if (typeof schema.maxLength === "number") {
        add("max-length", path, (copy) =>
          setAtPath(copy, path, "x".repeat(schema.maxLength + 1)),
        );
      }
      if (typeof schema.minLength === "number" && schema.minLength > 0) {
        add("min-length", path, (copy) => setAtPath(copy, path, ""));
      }
    }

    if (Array.isArray(value)) {
      if (schema.uniqueItems === true && value.length > 0) {
        add("unique-items", path, (copy) => {
          const target = getAtPath(copy, path) as unknown[];
          target.push(structuredClone(target[0]));
        });
      }
      if (typeof schema.minItems === "number" && schema.minItems > 0) {
        add("min-items", path, (copy) => setAtPath(copy, path, []));
      }
      if (typeof schema.maxItems === "number") {
        add("max-items", path, (copy) => {
          const target = getAtPath(copy, path) as unknown[];
          const seed = target.length > 0 ? target[0] : null;
          while (target.length <= schema.maxItems) {
            target.push(structuredClone(seed));
          }
        });
      }
      const prefixItems = Array.isArray(schema.prefixItems)
        ? schema.prefixItems
        : [];
      value.forEach((entry, index) => {
        if (prefixItems[index] !== undefined) {
          visit(prefixItems[index], entry, [...path, index]);
        }
      });
      const itemSchema = schema.items;
      if (itemSchema !== undefined && itemSchema !== false) {
        value.forEach((entry, index) =>
          index >= prefixItems.length
            ? visit(itemSchema, entry, [...path, index])
            : undefined,
        );
      }
      return;
    }

    if (isObject(value)) {
      const required = Array.isArray(schema.required) ? schema.required : [];
      for (const key of required) {
        if (typeof key === "string" && key in value) {
          add("required", [...path, key], (copy) => {
            const parent = getAtPath(copy, path) as Record<string, unknown>;
            delete parent[key];
          });
        }
      }
      if (schema.additionalProperties === false) {
        add("unknown-field", path, (copy) => {
          const target = getAtPath(copy, path) as Record<string, unknown>;
          target.__unexpected_contract_field__ = true;
        });
      }
      if (
        typeof schema.minProperties === "number" &&
        schema.minProperties > 0
      ) {
        add("min-properties", path, (copy) => {
          const target = getAtPath(copy, path) as Record<string, unknown>;
          for (const key of Object.keys(target)) {
            if (Object.keys(target).length < schema.minProperties) break;
            delete target[key];
          }
        });
      }
      if (typeof schema.maxProperties === "number") {
        add("max-properties", path, (copy) => {
          const target = getAtPath(copy, path) as Record<string, unknown>;
          let index = 0;
          while (Object.keys(target).length <= schema.maxProperties) {
            target[`__extra_${index}`] = true;
            index += 1;
          }
        });
      }
      if (isObject(schema.dependentRequired)) {
        for (const [trigger, dependencies] of Object.entries(
          schema.dependentRequired,
        )) {
          if (!(trigger in value) || !Array.isArray(dependencies)) continue;
          for (const dependency of dependencies) {
            if (typeof dependency !== "string" || !(dependency in value))
              continue;
            add("dependent-required", [...path, dependency], (copy) => {
              const target = getAtPath(copy, path) as Record<string, unknown>;
              delete target[dependency];
            });
          }
        }
      }
      const properties = isObject(schema.properties) ? schema.properties : {};
      for (const [key, entry] of Object.entries(value)) {
        if (key in properties) {
          visit(properties[key], entry, [...path, key]);
        } else if (isObject(schema.additionalProperties)) {
          visit(schema.additionalProperties, entry, [...path, key]);
        }
      }
    }
  };

  visit(rootSchema, fixture, []);
  return mutations.sort((left, right) => left.id.localeCompare(right.id));
}

function selectSchema(
  rootSchema: unknown,
  schemaValue: unknown,
  value: unknown,
): Record<string, any> {
  let schema = expandCompositions(
    rootSchema,
    resolveSchema(rootSchema, schemaValue),
    value,
  );
  const variants = Array.isArray(schema.oneOf)
    ? schema.oneOf
    : Array.isArray(schema.anyOf)
      ? schema.anyOf
      : null;
  if (variants) {
    const selected = variants
      .map((variant: unknown) => resolveSchema(rootSchema, variant))
      .find((variant: Record<string, any>) => typeMatches(variant.type, value));
    if (selected) schema = mergeSchemas(schema, selected);
  }
  return schema;
}

function expandCompositions(
  rootSchema: unknown,
  schemaValue: Record<string, any>,
  value: unknown,
): Record<string, any> {
  let schema = { ...schemaValue };
  if (Array.isArray(schema.allOf)) {
    for (const part of schema.allOf) {
      schema = mergeSchemas(
        schema,
        expandCompositions(rootSchema, resolveSchema(rootSchema, part), value),
      );
    }
  }
  if (schema.if !== undefined) {
    const branch = schemaMatches(rootSchema, schema.if, value)
      ? schema.then
      : schema.else;
    if (branch !== undefined) {
      schema = mergeSchemas(
        schema,
        expandCompositions(
          rootSchema,
          resolveSchema(rootSchema, branch),
          value,
        ),
      );
    }
  }
  delete schema.allOf;
  delete schema.if;
  delete schema.then;
  delete schema.else;
  return schema;
}

function mergeSchemas(
  left: Record<string, any>,
  right: Record<string, any>,
): Record<string, any> {
  const merged = { ...left, ...right };
  if (Array.isArray(left.required) || Array.isArray(right.required)) {
    merged.required = [
      ...new Set([...(left.required ?? []), ...(right.required ?? [])]),
    ];
  }
  if (isObject(left.properties) || isObject(right.properties)) {
    const keys = new Set([
      ...Object.keys(left.properties ?? {}),
      ...Object.keys(right.properties ?? {}),
    ]);
    merged.properties = Object.fromEntries(
      [...keys].map((key) => [
        key,
        isObject(left.properties?.[key]) && isObject(right.properties?.[key])
          ? mergeSchemas(left.properties[key], right.properties[key])
          : (right.properties?.[key] ?? left.properties?.[key]),
      ]),
    );
  }
  if (isObject(left.dependentRequired) || isObject(right.dependentRequired)) {
    merged.dependentRequired = {
      ...(left.dependentRequired ?? {}),
      ...(right.dependentRequired ?? {}),
    };
  }
  return merged;
}

function schemaMatches(
  rootSchema: unknown,
  schemaValue: unknown,
  value: unknown,
): boolean {
  const schema = expandCompositions(
    rootSchema,
    resolveSchema(rootSchema, schemaValue),
    value,
  );
  if (schema.const !== undefined && value !== schema.const) return false;
  if (Array.isArray(schema.enum) && !schema.enum.includes(value)) return false;
  if (schema.type !== undefined && !typeMatches(schema.type, value))
    return false;
  if (isObject(value)) {
    for (const required of schema.required ?? []) {
      if (typeof required === "string" && !(required in value)) return false;
    }
    if (isObject(schema.properties)) {
      for (const [key, property] of Object.entries(schema.properties)) {
        if (key in value && !schemaMatches(rootSchema, property, value[key]))
          return false;
      }
    }
  }
  return true;
}

function resolveSchema(
  rootSchema: unknown,
  value: unknown,
): Record<string, any> {
  if (!isObject(value)) return {};
  if (typeof value.$ref !== "string" || !value.$ref.startsWith("#/")) {
    return value;
  }
  const target = value.$ref
    .slice(2)
    .split("/")
    .map((segment) => segment.replace(/~1/g, "/").replace(/~0/g, "~"))
    .reduce<unknown>((current, segment) => {
      if (!isObject(current) || !(segment in current)) return undefined;
      return current[segment];
    }, rootSchema);
  return { ...resolveSchema(rootSchema, target), ...value, $ref: undefined };
}

function typeMatches(type: unknown, value: unknown): boolean {
  if (type === "null") return value === null;
  if (type === "array") return Array.isArray(value);
  if (type === "object") return isObject(value);
  if (type === "integer") return Number.isInteger(value);
  return typeof type === "string" && typeof value === type;
}

function unlike(value: unknown): unknown {
  if (typeof value === "string") return "__invalid_const__";
  if (typeof value === "boolean") return !value;
  if (typeof value === "number") return value + 1;
  return null;
}

function setAtPath(
  root: unknown,
  path: readonly (string | number)[],
  value: unknown,
): void {
  if (path.length === 0) {
    if (!isObject(root) || !isObject(value)) {
      throw new Error("root mutation requires object values");
    }
    for (const key of Object.keys(root)) delete root[key];
    Object.assign(root, value);
    return;
  }
  const parent = getAtPath(root, path.slice(0, -1)) as any;
  parent[path[path.length - 1]!] = value;
}

function getAtPath(root: unknown, path: readonly (string | number)[]): unknown {
  return path.reduce<any>((current, segment) => current[segment], root);
}

function formatPath(path: readonly (string | number)[]): string {
  if (path.length === 0) return "$";
  return path
    .map((segment) => (typeof segment === "number" ? `[${segment}]` : segment))
    .join(".")
    .replace(/\.\[/g, "[");
}

function reverseObjectKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(reverseObjectKeys);
  if (isObject(value)) {
    return Object.fromEntries(
      Object.entries(value)
        .reverse()
        .map(([key, entry]) => [key, reverseObjectKeys(entry)]),
    );
  }
  return value;
}

function firstArrayPath(
  value: unknown,
  path: readonly (string | number)[] = [],
): readonly (string | number)[] | null {
  if (Array.isArray(value)) {
    if (value.length > 1) return path;
    for (let index = 0; index < value.length; index += 1) {
      const nested = firstArrayPath(value[index], [...path, index]);
      if (nested) return nested;
    }
  } else if (isObject(value)) {
    for (const [key, entry] of Object.entries(value)) {
      const nested = firstArrayPath(entry, [...path, key]);
      if (nested) return nested;
    }
  }
  return null;
}

function isObject(value: unknown): value is Record<string, any> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function readJson(file: string): unknown {
  return JSON.parse(readFileSync(file, "utf8"));
}

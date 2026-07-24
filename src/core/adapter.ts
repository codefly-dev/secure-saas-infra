import { CloudProvider, PlatformBlueprint, PlatformCapability } from "./model";
import { assertBlueprint } from "./policy";

export interface AdapterDescriptor {
  cloud: CloudProvider;
  name: string;
  capabilities: ReadonlySet<PlatformCapability>;
}

export interface CloudAdapter<TPlan> {
  readonly descriptor: AdapterDescriptor;
  compile(blueprint: PlatformBlueprint): TPlan;
}

export function compileBlueprint<TPlan>(
  blueprint: PlatformBlueprint,
  adapter: CloudAdapter<TPlan>,
): TPlan {
  assertBlueprint(blueprint);

  const missing = blueprint.requiredCapabilities.filter(
    (capability) => !adapter.descriptor.capabilities.has(capability),
  );
  if (missing.length > 0) {
    throw new Error(
      `Cloud adapter '${adapter.descriptor.name}' does not support required capabilities: ${missing.join(", ")}.`,
    );
  }

  return adapter.compile(blueprint);
}

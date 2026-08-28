import { convexTest } from "convex-test";
import schema from "./schema";

const modules = import.meta.glob("./**/*.ts");

/** Builds a test backend whose public calls carry a stable owner identity while `run` remains available for fixture inspection. */
export function authenticatedTest(subject = "test-owner") {
  const backend = convexTest(schema, modules);
  const authenticated = backend.withIdentity({ subject, issuer: "https://test-idp.example", name: subject });
  return Object.assign(backend, {
    query: authenticated.query,
    mutation: authenticated.mutation,
    action: authenticated.action,
  });
}

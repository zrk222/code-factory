/* eslint-disable */
/**
 * Generated `api` utility.
 *
 * THIS CODE IS AUTOMATICALLY GENERATED.
 *
 * To regenerate, run `npx convex dev`.
 * @module
 */

import type * as access from "../access.js";
import type * as adversarialApprovalDomain from "../adversarialApprovalDomain.js";
import type * as agentComposer from "../agentComposer.js";
import type * as agentComposerDomain from "../agentComposerDomain.js";
import type * as agentExchange from "../agentExchange.js";
import type * as agentExchangeDomain from "../agentExchangeDomain.js";
import type * as agentIntelligence from "../agentIntelligence.js";
import type * as agentIntelligenceDomain from "../agentIntelligenceDomain.js";
import type * as authoritativeSources from "../authoritativeSources.js";
import type * as blueprints from "../blueprints.js";
import type * as budget from "../budget.js";
import type * as concierge from "../concierge.js";
import type * as conciergeDomain from "../conciergeDomain.js";
import type * as control from "../control.js";
import type * as credits from "../credits.js";
import type * as dashboard from "../dashboard.js";
import type * as databaseTools from "../databaseTools.js";
import type * as domain from "../domain.js";
import type * as enterpriseGovernance from "../enterpriseGovernance.js";
import type * as enterpriseIdentity from "../enterpriseIdentity.js";
import type * as enterpriseSecurity from "../enterpriseSecurity.js";
import type * as execution from "../execution.js";
import type * as incidents from "../incidents.js";
import type * as inferenceBindings from "../inferenceBindings.js";
import type * as knowledgeConnectors from "../knowledgeConnectors.js";
import type * as lifecycle from "../lifecycle.js";
import type * as memory from "../memory.js";
import type * as operations from "../operations.js";
import type * as pricing from "../pricing.js";
import type * as productionReadinessDomain from "../productionReadinessDomain.js";
import type * as recipeLab from "../recipeLab.js";
import type * as recipeLabDomain from "../recipeLabDomain.js";
import type * as releases from "../releases.js";
import type * as runtimeAdapters from "../runtimeAdapters.js";
import type * as seed from "../seed.js";
import type * as sourceAdmission from "../sourceAdmission.js";
import type * as trust from "../trust.js";

import type {
  ApiFromModules,
  FilterApi,
  FunctionReference,
} from "convex/server";

declare const fullApi: ApiFromModules<{
  access: typeof access;
  adversarialApprovalDomain: typeof adversarialApprovalDomain;
  agentComposer: typeof agentComposer;
  agentComposerDomain: typeof agentComposerDomain;
  agentExchange: typeof agentExchange;
  agentExchangeDomain: typeof agentExchangeDomain;
  agentIntelligence: typeof agentIntelligence;
  agentIntelligenceDomain: typeof agentIntelligenceDomain;
  authoritativeSources: typeof authoritativeSources;
  blueprints: typeof blueprints;
  budget: typeof budget;
  concierge: typeof concierge;
  conciergeDomain: typeof conciergeDomain;
  control: typeof control;
  credits: typeof credits;
  dashboard: typeof dashboard;
  databaseTools: typeof databaseTools;
  domain: typeof domain;
  enterpriseGovernance: typeof enterpriseGovernance;
  enterpriseIdentity: typeof enterpriseIdentity;
  enterpriseSecurity: typeof enterpriseSecurity;
  execution: typeof execution;
  incidents: typeof incidents;
  inferenceBindings: typeof inferenceBindings;
  knowledgeConnectors: typeof knowledgeConnectors;
  lifecycle: typeof lifecycle;
  memory: typeof memory;
  operations: typeof operations;
  pricing: typeof pricing;
  productionReadinessDomain: typeof productionReadinessDomain;
  recipeLab: typeof recipeLab;
  recipeLabDomain: typeof recipeLabDomain;
  releases: typeof releases;
  runtimeAdapters: typeof runtimeAdapters;
  seed: typeof seed;
  sourceAdmission: typeof sourceAdmission;
  trust: typeof trust;
}>;

/**
 * A utility for referencing Convex functions in your app's public API.
 *
 * Usage:
 * ```js
 * const myFunctionReference = api.myModule.myFunction;
 * ```
 */
export declare const api: FilterApi<
  typeof fullApi,
  FunctionReference<any, "public">
>;

/**
 * A utility for referencing Convex functions in your app's internal API.
 *
 * Usage:
 * ```js
 * const myFunctionReference = internal.myModule.myFunction;
 * ```
 */
export declare const internal: FilterApi<
  typeof fullApi,
  FunctionReference<any, "internal">
>;

export declare const components: {};

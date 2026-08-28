import { ClerkProvider, useAuth } from "@clerk/react";
import { ConvexReactClient } from "convex/react";
import { ConvexProviderWithClerk } from "convex/react-clerk";
import { ArrowLeft, ShieldCheck } from "lucide-react";
import { AuthBoundary } from "./AuthBoundary";

export type HostedBrowserConfiguration = {
  deploymentUrl: string | undefined;
  clerkPublishableKey: string | undefined;
};

const placeholderPattern = /your-|placeholder|example\.com|localhost|127\.0\.0\.1/i;

/** Returns true only for a hosted Convex URL and a non-placeholder Clerk publishable key. */
export function isHostedConfigurationValid(configuration: HostedBrowserConfiguration) {
  const { deploymentUrl, clerkPublishableKey } = configuration;
  if (!deploymentUrl || !clerkPublishableKey) return false;
  if (placeholderPattern.test(`${deploymentUrl} ${clerkPublishableKey}`)) return false;
  try {
    const url = new URL(deploymentUrl);
    return url.protocol === "https:" && url.hostname.endsWith(".convex.cloud") && /^pk_(?:test|live)_[A-Za-z0-9_-]{16,}$/.test(clerkPublishableKey);
  } catch {
    return false;
  }
}

function AccessProvisioning() {
  return (
    <main className="access-provisioning" data-testid="access-provisioning">
      <a href="/" className="access-back"><ArrowLeft size={16} /> Back to Agent Oven</a>
      <section>
        <span className="access-icon"><ShieldCheck size={28} /></span>
        <p className="public-kicker">Protected workspace access</p>
        <h1>Your Agent Oven workspace is being prepared.</h1>
        <p>The public site is live. Account access opens only after the hosted identity boundary is verified, so no workspace or agent data is exposed during activation.</p>
        <div className="access-state"><span /><div><small>CONTROL PLANE</small><strong>Hosted Convex connected</strong></div></div>
        <div className="access-state pending"><span /><div><small>IDENTITY</small><strong>Account access provisioning</strong></div></div>
        <p className="access-note">Already invited? Return shortly or contact your Agent Oven administrator.</p>
      </section>
    </main>
  );
}

/** Mounts operational providers only after all hosted public configuration is valid. */
export function HostedAppBoundary({ configuration }: { configuration: HostedBrowserConfiguration }) {
  if (!isHostedConfigurationValid(configuration)) return <AccessProvisioning />;
  const convex = new ConvexReactClient(configuration.deploymentUrl!);
  return (
    <ClerkProvider
      publishableKey={configuration.clerkPublishableKey!}
      signInFallbackRedirectUrl="/app"
      signUpFallbackRedirectUrl="/app"
      afterSignOutUrl="/"
    >
      <ConvexProviderWithClerk client={convex} useAuth={useAuth}>
        <AuthBoundary />
      </ConvexProviderWithClerk>
    </ClerkProvider>
  );
}

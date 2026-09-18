package io.github.hectorvent.floci.services.iam.model;

import java.util.List;

/**
 * Full IAM context for the calling identity, used by the enforcement filter.
 *
 * <p>Carries all inputs required for the complete AWS policy evaluation algorithm:
 * <ul>
 *   <li>{@code identityPolicies} — inline + attached policies of the user, role, and groups</li>
 *   <li>{@code sessionPolicyDocument} — optional inline session policy from AssumeRole (Phase 3)</li>
 *   <li>{@code boundaryPolicyDocument} — optional permissions boundary document (Phase 3)</li>
 *   <li>{@code scpLevels} — optional effective service control policies for the caller's
 *       account, one list of policy documents per organization level (root, each OU on the
 *       path, account). An action must be allowed at every level and denied at none.
 *       {@code null} when SCPs don't apply (no organization, management account, or SCP
 *       enforcement disabled).</li>
 *   <li>{@code principal} — the principal the request arrives as, which a resource policy's
 *       {@code Principal} is matched against and whose account decides same-account from
 *       cross-account. {@code null} when the caller could not be identified, which leaves the
 *       decision to the identity policies alone.</li>
 * </ul>
 */
public record CallerContext(
        List<String> identityPolicies,
        String sessionPolicyDocument,
        String boundaryPolicyDocument,
        List<List<String>> scpLevels,
        RequestPrincipal principal
) {
    /** Source-compatible constructor for callers predating SCP support. */
    public CallerContext(List<String> identityPolicies, String sessionPolicyDocument,
                         String boundaryPolicyDocument) {
        this(identityPolicies, sessionPolicyDocument, boundaryPolicyDocument, null, null);
    }

    /** Source-compatible constructor for callers predating resource-policy support. */
    public CallerContext(List<String> identityPolicies, String sessionPolicyDocument,
                         String boundaryPolicyDocument, List<List<String>> scpLevels) {
        this(identityPolicies, sessionPolicyDocument, boundaryPolicyDocument, scpLevels, null);
    }

    /** Convenience factory: no session policy, no boundary, no SCPs, no identified principal. */
    public static CallerContext of(List<String> identityPolicies) {
        return new CallerContext(identityPolicies, null, null, null, null);
    }

    /** Copy of this context with the effective SCP levels attached. */
    public CallerContext withScpLevels(List<List<String>> levels) {
        return new CallerContext(identityPolicies, sessionPolicyDocument, boundaryPolicyDocument,
                levels, principal);
    }

    /** Copy of this context with the request's principal attached. */
    public CallerContext withPrincipal(RequestPrincipal requestPrincipal) {
        return new CallerContext(identityPolicies, sessionPolicyDocument, boundaryPolicyDocument,
                scpLevels, requestPrincipal);
    }
}

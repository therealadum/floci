package io.github.hectorvent.floci.services.iam.model;

import java.util.List;

/**
 * The resource-based policies attached to one resource, with the two facts the evaluator needs
 * about the resource itself.
 *
 * <ul>
 *   <li>{@code documents} — the policy documents. Empty when the resource carries none; the
 *       resource is still described, because a cross-account request against a resource with no
 *       policy is refused and only a present {@code ResourcePolicies} can say so.</li>
 *   <li>{@code ownerAccountId} — the account that owns the resource. Null when it cannot be
 *       found, which makes every request against it same-account and leaves the decision to the
 *       identity policies alone.</li>
 *   <li>{@code rootOfAuthority} — true for a KMS key policy. A key policy is the whole of the
 *       authority over its key: an identity policy grants on a key only where the key policy
 *       delegates to the account, which is what the {@code arn:aws:iam::<account>:root}
 *       statement of the default key policy does.</li>
 * </ul>
 */
public record ResourcePolicies(
        List<String> documents,
        String ownerAccountId,
        boolean rootOfAuthority
) {

    /** An ordinary resource policy: a bucket policy, a secret's resource policy. */
    public static ResourcePolicies of(List<String> documents, String ownerAccountId) {
        return new ResourcePolicies(documents == null ? List.of() : documents, ownerAccountId, false);
    }

    /** A KMS key policy, which is the root of authority over its key. */
    public static ResourcePolicies keyPolicy(List<String> documents, String ownerAccountId) {
        return new ResourcePolicies(documents == null ? List.of() : documents, ownerAccountId, true);
    }

    public boolean isEmpty() {
        return documents == null || documents.isEmpty();
    }
}

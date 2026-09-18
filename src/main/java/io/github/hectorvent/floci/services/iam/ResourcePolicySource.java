package io.github.hectorvent.floci.services.iam;

import io.github.hectorvent.floci.services.iam.model.ResourcePolicies;

import java.util.Optional;

/**
 * Supplies the resource-based policies attached to one resource, for the service that owns it.
 *
 * <p>Implemented once per service that holds resource policies — S3 bucket policies, KMS key
 * policies, a secret's resource policy — and collected by {@link ResourcePolicyLookup}, which
 * {@code IamEnforcementFilter} asks. A service joins by adding an {@code @ApplicationScoped}
 * implementation beside its own service class; nothing in IAM or in the filter changes.</p>
 *
 * <p>IAM never depends on those services: the dependency runs the other way, exactly as it does
 * for {@link ScpProvider}.</p>
 */
public interface ResourcePolicySource {

    /**
     * @param resourceArn the ARN the request targets
     * @return the resource's policies and owning account, or empty when this source does not own
     *         the ARN, or cannot name one resource from it — a wildcard ARN among them. An owned
     *         resource carrying no policy is still described, with no documents, because a
     *         cross-account request against it must be refused.
     */
    Optional<ResourcePolicies> policiesFor(String resourceArn);
}

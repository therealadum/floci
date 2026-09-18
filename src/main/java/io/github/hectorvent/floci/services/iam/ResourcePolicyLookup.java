package io.github.hectorvent.floci.services.iam;

import io.github.hectorvent.floci.services.iam.model.ResourcePolicies;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.util.Optional;

/**
 * The one lookup from a resource ARN to the resource policies attached to it.
 *
 * <p>Every {@link ResourcePolicySource} is resolved lazily, the way {@code Instance<ScpProvider>}
 * is, so IAM carries no dependency on the services that hold the policies and a service can be
 * disabled without breaking enforcement. The first source that claims the ARN answers; the rest
 * are not asked.</p>
 */
@ApplicationScoped
public class ResourcePolicyLookup {

    private static final Logger LOG = Logger.getLogger(ResourcePolicyLookup.class);

    private final Instance<ResourcePolicySource> sources;

    @Inject
    public ResourcePolicyLookup(Instance<ResourcePolicySource> sources) {
        this.sources = sources;
    }

    /**
     * @return the policies of the resource the ARN names, or empty when no source owns it — which
     *         leaves the request to its identity policies alone, exactly as before this lookup
     *         existed.
     */
    public ResourcePolicies policiesFor(String resourceArn) {
        if (resourceArn == null || resourceArn.isBlank() || "*".equals(resourceArn)) {
            return null;
        }
        for (ResourcePolicySource source : sources) {
            Optional<ResourcePolicies> policies;
            try {
                policies = source.policiesFor(resourceArn);
            } catch (RuntimeException e) {
                // A source that cannot read its own store must not decide the request by
                // accident: skip it and let the remaining sources and the identity policies say.
                LOG.debugv(e, "Resource policy source {0} failed for {1}",
                        source.getClass().getSimpleName(), resourceArn);
                continue;
            }
            if (policies != null && policies.isPresent()) {
                return policies.get();
            }
        }
        return null;
    }
}

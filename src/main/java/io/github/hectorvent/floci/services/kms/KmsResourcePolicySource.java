package io.github.hectorvent.floci.services.kms;

import io.github.hectorvent.floci.services.iam.ResourcePolicySource;
import io.github.hectorvent.floci.services.iam.model.ResourcePolicies;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.util.List;
import java.util.Optional;

/**
 * The key policy of an {@code arn:aws:kms:...:key/...} target, declared as the root of authority
 * over its key: an identity policy grants on a key only where the key policy delegates to the
 * account, which is what the {@code arn:aws:iam::<account>:root} statement KMS writes into every
 * default key policy does.
 */
@ApplicationScoped
public class KmsResourcePolicySource implements ResourcePolicySource {

    private final KmsService kmsService;

    @Inject
    public KmsResourcePolicySource(KmsService kmsService) {
        this.kmsService = kmsService;
    }

    @Override
    public Optional<ResourcePolicies> policiesFor(String resourceArn) {
        return kmsService.keyOwnerPolicy(resourceArn)
                .map(owned -> ResourcePolicies.keyPolicy(
                        owned.policy() == null || owned.policy().isBlank()
                                ? List.of() : List.of(owned.policy()),
                        owned.ownerAccountId()));
    }
}

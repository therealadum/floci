package io.github.hectorvent.floci.services.secretsmanager;

import io.github.hectorvent.floci.services.iam.ResourcePolicySource;
import io.github.hectorvent.floci.services.iam.model.ResourcePolicies;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.util.List;
import java.util.Optional;

/**
 * The resource policy of an {@code arn:aws:secretsmanager:...:secret:...} target, for the one
 * policy evaluator. A secret that exists but carries no policy is still described, so a caller
 * outside its owning account is refused by the absence.
 */
@ApplicationScoped
public class SecretsManagerResourcePolicySource implements ResourcePolicySource {

    private final SecretsManagerService secretsManagerService;

    @Inject
    public SecretsManagerResourcePolicySource(SecretsManagerService secretsManagerService) {
        this.secretsManagerService = secretsManagerService;
    }

    @Override
    public Optional<ResourcePolicies> policiesFor(String resourceArn) {
        return secretsManagerService.secretOwnerPolicy(resourceArn)
                .map(owned -> ResourcePolicies.of(
                        owned.policy() == null || owned.policy().isBlank()
                                ? List.of() : List.of(owned.policy()),
                        owned.ownerAccountId()));
    }
}

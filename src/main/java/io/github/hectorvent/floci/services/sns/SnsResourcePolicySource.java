package io.github.hectorvent.floci.services.sns;

import io.github.hectorvent.floci.services.iam.ResourcePolicySource;
import io.github.hectorvent.floci.services.iam.model.ResourcePolicies;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.util.List;
import java.util.Optional;

/**
 * The topic policy of an {@code arn:aws:sns:<region>:<account>:<topic>} target, for the one
 * policy evaluator.
 *
 * <p>Until this existed a topic policy was stored by {@code SetTopicAttributes} and read back by
 * {@code GetTopicAttributes}, and nothing ever evaluated it: every SNS call was decided by the
 * caller's identity policies alone. That made two things wrong at once. A service principal such
 * as {@code events.amazonaws.com} has no identity policy, so the statement a topic must carry for
 * EventBridge to publish to it meant nothing; and a principal in another account reached a topic
 * with no statement for it, which AWS refuses.</p>
 *
 * <p>A topic that exists and carries no policy is still described, with no documents, because a
 * cross-account request against it must be refused by that absence.</p>
 */
@ApplicationScoped
public class SnsResourcePolicySource implements ResourcePolicySource {

    private static final String SNS_ARN_PREFIX = "arn:aws:sns:";

    private final SnsService snsService;

    @Inject
    public SnsResourcePolicySource(SnsService snsService) {
        this.snsService = snsService;
    }

    @Override
    public Optional<ResourcePolicies> policiesFor(String resourceArn) {
        if (resourceArn == null || !resourceArn.startsWith(SNS_ARN_PREFIX)) {
            return Optional.empty();
        }
        return snsService.topicOwnerPolicy(resourceArn)
                .map(owned -> ResourcePolicies.of(
                        owned.policy() == null || owned.policy().isBlank()
                                ? List.of() : List.of(owned.policy()),
                        owned.ownerAccountId()));
    }
}

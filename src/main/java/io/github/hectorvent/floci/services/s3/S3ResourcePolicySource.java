package io.github.hectorvent.floci.services.s3;

import io.github.hectorvent.floci.services.iam.ResourcePolicySource;
import io.github.hectorvent.floci.services.iam.model.ResourcePolicies;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.util.List;
import java.util.Optional;

/**
 * The bucket policy of an {@code arn:aws:s3:::bucket[/key]} target, for the one policy evaluator.
 *
 * <p>An S3 ARN carries no account, so the owner comes from the account partition the bucket is
 * stored in. A bucket that exists but carries no policy is still described: a caller outside its
 * owning account is refused by the absence.</p>
 */
@ApplicationScoped
public class S3ResourcePolicySource implements ResourcePolicySource {

    private static final String S3_ARN_PREFIX = "arn:aws:s3:::";

    private final S3Service s3Service;

    @Inject
    public S3ResourcePolicySource(S3Service s3Service) {
        this.s3Service = s3Service;
    }

    @Override
    public Optional<ResourcePolicies> policiesFor(String resourceArn) {
        if (resourceArn == null || !resourceArn.startsWith(S3_ARN_PREFIX)) {
            return Optional.empty();
        }
        String tail = resourceArn.substring(S3_ARN_PREFIX.length());
        int slash = tail.indexOf('/');
        String bucketName = slash < 0 ? tail : tail.substring(0, slash);
        if (bucketName.isEmpty() || bucketName.contains("*")) {
            return Optional.empty();
        }
        return s3Service.bucketOwnerPolicy(bucketName)
                .map(owned -> ResourcePolicies.of(
                        owned.policy() == null || owned.policy().isBlank()
                                ? List.of() : List.of(owned.policy()),
                        owned.ownerAccountId()));
    }
}

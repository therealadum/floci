package io.github.hectorvent.floci.services.iam.model;

/**
 * The principal a request arrives as, in the forms a resource policy's {@code Principal} can
 * name it by.
 *
 * <ul>
 *   <li>{@code accountId} — the account the principal belongs to. It is what decides whether a
 *       request against a resource is same-account or cross-account.</li>
 *   <li>{@code arn} — the principal's own ARN: an IAM user ARN, an assumed-role session ARN
 *       ({@code arn:aws:sts::<account>:assumed-role/<Role>/<session>}), or the account root
 *       ARN for floci's account-root principal.</li>
 *   <li>{@code roleArn} — the role behind an assumed-role session, so a key or bucket policy
 *       naming the role ARN matches every session of that role, as it does on AWS. Null for
 *       every other principal.</li>
 *   <li>{@code service} — the service principal, for a caller a service makes on its own
 *       behalf ({@code cloudfront.amazonaws.com}). Null otherwise.</li>
 *   <li>{@code federated} — the federated issuer, for a web-identity or SAML caller. Null
 *       otherwise.</li>
 * </ul>
 */
public record RequestPrincipal(
        String accountId,
        String arn,
        String roleArn,
        String service,
        String federated
) {

    /** An IAM user identified by its user ARN. */
    public static RequestPrincipal user(String accountId, String userArn) {
        return new RequestPrincipal(accountId, userArn, null, null, null);
    }

    /** An assumed-role session, which its role's ARN also names. */
    public static RequestPrincipal assumedRole(String accountId, String sessionArn, String roleArn) {
        return new RequestPrincipal(accountId, sessionArn, roleArn, null, null);
    }

    /** The account root: {@code arn:aws:iam::<account>:root}. */
    public static RequestPrincipal accountRoot(String accountId) {
        return new RequestPrincipal(accountId, "arn:aws:iam::" + accountId + ":root", null, null, null);
    }

    /** A service acting on its own behalf. */
    public static RequestPrincipal service(String accountId, String serviceName) {
        return new RequestPrincipal(accountId, null, null, serviceName, null);
    }

    /** A federated identity, named by its issuer or SAML provider ARN. */
    public static RequestPrincipal federated(String accountId, String issuer) {
        return new RequestPrincipal(accountId, null, null, null, issuer);
    }
}

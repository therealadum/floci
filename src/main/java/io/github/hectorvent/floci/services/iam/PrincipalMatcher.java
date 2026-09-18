package io.github.hectorvent.floci.services.iam;

import io.github.hectorvent.floci.services.iam.model.PolicyStatement;
import io.github.hectorvent.floci.services.iam.model.RequestPrincipal;

import java.util.List;
import java.util.Map;

/**
 * Matches a statement's {@code Principal} or {@code NotPrincipal} against the principal a
 * request arrives as. The one place a principal in a policy document is read, so a bucket
 * policy, a key policy and a secret's resource policy all mean the same thing by one.
 *
 * <p>The match is graded, because AWS grades it. A statement naming the caller itself — its
 * user ARN, its assumed-role session ARN, the role behind that session, a service or a
 * federated issuer — grants on its own inside the resource's account. A statement naming only
 * an account delegates to that account's IAM instead: it says "whatever IAM in this account
 * allows", so the caller still needs an identity policy. {@link IamPolicyEvaluator} reads the
 * grade to tell the two apart.
 *
 * <p>Principal values are compared exactly, never as globs: {@code *} is the only wildcard AWS
 * accepts in a principal, and it is handled as its own case.
 */
public final class PrincipalMatcher {

    /** How strongly a statement names the caller. */
    public enum Match {
        /** The statement does not apply to this caller. */
        NONE,
        /** The statement names the caller's account, and so delegates to that account's IAM. */
        ACCOUNT,
        /** The statement names the caller itself. */
        DIRECT
    }

    private PrincipalMatcher() {
    }

    /**
     * @return how the statement names {@code principal}, or {@link Match#NONE} when it does not,
     *         when the statement carries no principal at all — an identity-shaped statement in a
     *         resource policy grants nothing — or when the caller could not be identified.
     */
    public static Match match(PolicyStatement stmt, RequestPrincipal principal) {
        if (principal == null) {
            return Match.NONE;
        }
        if (stmt.getPrincipals() != null) {
            return matchAny(stmt.getPrincipals(), principal, true);
        }
        if (stmt.getNotPrincipals() != null) {
            // NotPrincipal applies to every principal it does not list. The role behind a session
            // is not expanded here: AWS requires a NotPrincipal that means to exclude a role to
            // list both the role ARN and its session ARN, and expanding would exclude sessions
            // the policy never named.
            return matchAny(stmt.getNotPrincipals(), principal, false) == Match.NONE
                    ? Match.DIRECT
                    : Match.NONE;
        }
        return Match.NONE;
    }

    private static Match matchAny(Map<String, List<String>> principals, RequestPrincipal principal,
                                  boolean expandRoleToSessions) {
        Match strongest = Match.NONE;
        for (Map.Entry<String, List<String>> entry : principals.entrySet()) {
            for (String value : entry.getValue()) {
                Match match = matchOne(entry.getKey(), value, principal, expandRoleToSessions);
                if (match == Match.DIRECT) {
                    return Match.DIRECT;
                }
                if (match == Match.ACCOUNT) {
                    strongest = Match.ACCOUNT;
                }
            }
        }
        return strongest;
    }

    private static Match matchOne(String type, String value, RequestPrincipal principal,
                                  boolean expandRoleToSessions) {
        if (value == null) {
            return Match.NONE;
        }
        if ("*".equals(value)) {
            // Everyone, whatever the principal type: the statement names this caller as directly
            // as it names any other.
            return Match.DIRECT;
        }
        return switch (type) {
            case "AWS" -> matchAws(value, principal, expandRoleToSessions);
            case "Service" -> value.equals(principal.service()) ? Match.DIRECT : Match.NONE;
            case "Federated" -> value.equals(principal.federated()) ? Match.DIRECT : Match.NONE;
            // CanonicalUser is an S3 ACL identity floci does not model as a request principal.
            default -> Match.NONE;
        };
    }

    private static Match matchAws(String value, RequestPrincipal principal,
                                  boolean expandRoleToSessions) {
        if (value.equals(principal.arn())) {
            return Match.DIRECT;
        }
        if (expandRoleToSessions && principal.roleArn() != null && value.equals(principal.roleArn())) {
            return Match.DIRECT;
        }
        String accountId = principal.accountId();
        if (accountId != null
                && (value.equals(accountId) || value.equals("arn:aws:iam::" + accountId + ":root"))) {
            return Match.ACCOUNT;
        }
        return Match.NONE;
    }
}

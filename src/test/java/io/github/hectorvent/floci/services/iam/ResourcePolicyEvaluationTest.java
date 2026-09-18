package io.github.hectorvent.floci.services.iam;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.services.iam.IamPolicyEvaluator.Decision;
import io.github.hectorvent.floci.services.iam.model.CallerContext;
import io.github.hectorvent.floci.services.iam.model.RequestPrincipal;
import io.github.hectorvent.floci.services.iam.model.ResourcePolicies;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Resource-based policy evaluation: {@code Principal} and {@code NotPrincipal} in a statement,
 * and AWS's cross-account meaning — inside one account either policy suffices, across accounts
 * both must allow, an explicit deny anywhere refuses, and a key policy is the root of authority.
 */
class ResourcePolicyEvaluationTest {

    private static final String OWNER = "111111111111";
    private static final String OTHER = "222222222222";
    private static final String BUCKET = "arn:aws:s3:::owner-bucket/object.txt";
    private static final String KEY = "arn:aws:kms:us-east-1:" + OWNER + ":key/k-1";

    private final IamPolicyEvaluator evaluator = new IamPolicyEvaluator(new ObjectMapper());

    private static final String ALLOW_GET = """
        {"Version":"2012-10-17","Statement":[
          {"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}""";
    private static final String ALLOW_ALL = """
        {"Version":"2012-10-17","Statement":[
          {"Effect":"Allow","Action":"*","Resource":"*"}]}""";
    private static final String NO_POLICY = """
        {"Version":"2012-10-17","Statement":[]}""";

    private static RequestPrincipal session(String account, String role) {
        return RequestPrincipal.assumedRole(
                account,
                "arn:aws:sts::" + account + ":assumed-role/" + role + "/floci-session",
                "arn:aws:iam::" + account + ":role/" + role);
    }

    private static RequestPrincipal user(String account, String name) {
        return RequestPrincipal.user(account, "arn:aws:iam::" + account + ":user/" + name);
    }

    private Decision decide(RequestPrincipal principal, String identityPolicy,
                            String resourcePolicy, String action, String resource) {
        return decide(principal, identityPolicy,
                resourcePolicy == null ? null : ResourcePolicies.of(List.of(resourcePolicy), OWNER),
                action, resource);
    }

    private Decision decide(RequestPrincipal principal, String identityPolicy,
                            ResourcePolicies resourcePolicies, String action, String resource) {
        CallerContext caller = CallerContext.of(
                identityPolicy == null ? List.of() : List.of(identityPolicy)).withPrincipal(principal);
        return evaluator.evaluate(caller, resourcePolicies, action, resource, Map.of());
    }

    private static String bucketPolicy(String principalJson, String effect) {
        return """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"%s","Principal":%s,"Action":"s3:GetObject",
               "Resource":"arn:aws:s3:::owner-bucket/*"}]}""".formatted(effect, principalJson);
    }

    // ── Principal forms ────────────────────────────────────────────────────────

    @Test
    void bareStarPrincipalGrantsInsideTheAccount() {
        assertEquals(Decision.ALLOW, decide(session(OWNER, "Reader"), NO_POLICY,
                bucketPolicy("\"*\"", "Allow"), "s3:GetObject", BUCKET));
    }

    @Test
    void awsStarPrincipalGrantsInsideTheAccount() {
        assertEquals(Decision.ALLOW, decide(session(OWNER, "Reader"), NO_POLICY,
                bucketPolicy("{\"AWS\":\"*\"}", "Allow"), "s3:GetObject", BUCKET));
    }

    @Test
    void sessionArnPrincipalGrantsWithoutAnIdentityPolicy() {
        assertEquals(Decision.ALLOW, decide(session(OWNER, "Reader"), NO_POLICY,
                bucketPolicy("{\"AWS\":\"arn:aws:sts::" + OWNER
                        + ":assumed-role/Reader/floci-session\"}", "Allow"),
                "s3:GetObject", BUCKET));
    }

    @Test
    void roleArnPrincipalMatchesItsAssumedRoleSessions() {
        assertEquals(Decision.ALLOW, decide(session(OWNER, "Reader"), NO_POLICY,
                bucketPolicy("{\"AWS\":\"arn:aws:iam::" + OWNER + ":role/Reader\"}", "Allow"),
                "s3:GetObject", BUCKET));
    }

    @Test
    void userArnPrincipalGrantsWithoutAnIdentityPolicy() {
        assertEquals(Decision.ALLOW, decide(user(OWNER, "deployer"), NO_POLICY,
                bucketPolicy("{\"AWS\":\"arn:aws:iam::" + OWNER + ":user/deployer\"}", "Allow"),
                "s3:GetObject", BUCKET));
    }

    @Test
    void anotherRolesArnDoesNotMatch() {
        assertEquals(Decision.DENY, decide(session(OWNER, "Reader"), NO_POLICY,
                bucketPolicy("{\"AWS\":\"arn:aws:iam::" + OWNER + ":role/Writer\"}", "Allow"),
                "s3:GetObject", BUCKET));
    }

    @Test
    void accountPrincipalAloneDelegatesToIamAndDoesNotGrantByItself() {
        // Principal: the account root. AWS reads that as "whatever IAM in that account allows",
        // so the caller still needs an identity policy.
        String policy = bucketPolicy("{\"AWS\":\"arn:aws:iam::" + OWNER + ":root\"}", "Allow");
        assertEquals(Decision.DENY,
                decide(session(OWNER, "Reader"), NO_POLICY, policy, "s3:GetObject", BUCKET));
        assertEquals(Decision.ALLOW,
                decide(session(OWNER, "Reader"), ALLOW_GET, policy, "s3:GetObject", BUCKET));
    }

    @Test
    void bareAccountIdIsTheSamePrincipalAsTheRootArn() {
        String policy = bucketPolicy("{\"AWS\":\"" + OWNER + "\"}", "Allow");
        assertEquals(Decision.ALLOW,
                decide(session(OWNER, "Reader"), ALLOW_GET, policy, "s3:GetObject", BUCKET));
    }

    @Test
    void servicePrincipalMatchesAServiceCaller() {
        assertEquals(Decision.ALLOW, decide(
                RequestPrincipal.service(OWNER, "cloudfront.amazonaws.com"), NO_POLICY,
                bucketPolicy("{\"Service\":\"cloudfront.amazonaws.com\"}", "Allow"),
                "s3:GetObject", BUCKET));
        assertEquals(Decision.DENY, decide(
                RequestPrincipal.service(OWNER, "lambda.amazonaws.com"), NO_POLICY,
                bucketPolicy("{\"Service\":\"cloudfront.amazonaws.com\"}", "Allow"),
                "s3:GetObject", BUCKET));
    }

    @Test
    void federatedPrincipalMatchesAFederatedCaller() {
        assertEquals(Decision.ALLOW, decide(
                RequestPrincipal.federated(OWNER, "accounts.google.com"), NO_POLICY,
                bucketPolicy("{\"Federated\":\"accounts.google.com\"}", "Allow"),
                "s3:GetObject", BUCKET));
    }

    // ── NotPrincipal ───────────────────────────────────────────────────────────

    @Test
    void notPrincipalDeniesEveryoneButTheNamedPrincipal() {
        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Deny","NotPrincipal":{"AWS":[
                 "arn:aws:iam::%1$s:role/Reader",
                 "arn:aws:sts::%1$s:assumed-role/Reader/floci-session"]},
               "Action":"s3:GetObject","Resource":"arn:aws:s3:::owner-bucket/*"}]}"""
                .formatted(OWNER);
        assertEquals(Decision.ALLOW,
                decide(session(OWNER, "Reader"), ALLOW_GET, policy, "s3:GetObject", BUCKET));
        assertEquals(Decision.DENY,
                decide(session(OWNER, "Writer"), ALLOW_GET, policy, "s3:GetObject", BUCKET));
    }

    @Test
    void notPrincipalNamingOnlyARoleStillDeniesItsSessions() {
        // AWS's own rule: a NotPrincipal that means to exclude a role must list the role ARN and
        // the assumed-role session ARN both. Naming the role alone leaves its sessions denied.
        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Deny","NotPrincipal":{"AWS":"arn:aws:iam::%s:role/Reader"},
               "Action":"s3:GetObject","Resource":"arn:aws:s3:::owner-bucket/*"}]}"""
                .formatted(OWNER);
        assertEquals(Decision.DENY,
                decide(session(OWNER, "Reader"), ALLOW_GET, policy, "s3:GetObject", BUCKET));
    }

    @Test
    void notPrincipalWithAllowGrantsEveryPrincipalNotNamed() {
        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","NotPrincipal":{"AWS":[
                 "arn:aws:iam::%1$s:role/Writer",
                 "arn:aws:sts::%1$s:assumed-role/Writer/floci-session"]},
               "Action":"s3:GetObject","Resource":"arn:aws:s3:::owner-bucket/*"}]}"""
                .formatted(OWNER);
        assertEquals(Decision.ALLOW,
                decide(session(OWNER, "Reader"), NO_POLICY, policy, "s3:GetObject", BUCKET));
        assertEquals(Decision.DENY,
                decide(session(OWNER, "Writer"), NO_POLICY, policy, "s3:GetObject", BUCKET));
    }

    // ── Cross account ──────────────────────────────────────────────────────────

    @Test
    void crossAccountNeedsBothPolicies() {
        String namesTheRole = bucketPolicy(
                "{\"AWS\":\"arn:aws:iam::" + OTHER + ":role/Reader\"}", "Allow");
        // Resource policy alone is not enough across accounts.
        assertEquals(Decision.DENY,
                decide(session(OTHER, "Reader"), NO_POLICY, namesTheRole, "s3:GetObject", BUCKET));
        // Identity policy alone is not enough either: a bucket with no policy at all refuses
        // every caller outside its own account.
        assertEquals(Decision.DENY,
                decide(session(OTHER, "Reader"), ALLOW_GET,
                        ResourcePolicies.of(List.of(), OWNER), "s3:GetObject", BUCKET));
        // Both, and the request is allowed.
        assertEquals(Decision.ALLOW,
                decide(session(OTHER, "Reader"), ALLOW_GET, namesTheRole, "s3:GetObject", BUCKET));
    }

    @Test
    void crossAccountAccountPrincipalAlsoNeedsTheIdentityPolicy() {
        String namesTheAccount = bucketPolicy("{\"AWS\":\"" + OTHER + "\"}", "Allow");
        assertEquals(Decision.DENY,
                decide(session(OTHER, "Reader"), NO_POLICY, namesTheAccount, "s3:GetObject", BUCKET));
        assertEquals(Decision.ALLOW,
                decide(session(OTHER, "Reader"), ALLOW_GET, namesTheAccount, "s3:GetObject", BUCKET));
    }

    @Test
    void explicitDenyInAResourcePolicyRefusesTheOwningAccountsAdministrator() {
        String policy = bucketPolicy("\"*\"", "Deny");
        assertEquals(Decision.DENY,
                decide(session(OWNER, "Administrator"), ALLOW_ALL, policy, "s3:GetObject", BUCKET));
    }

    @Test
    void aDenyNamingAnotherPrincipalDoesNotRefuseThisOne() {
        String policy = bucketPolicy(
                "{\"AWS\":\"arn:aws:iam::" + OWNER + ":role/Writer\"}", "Deny");
        assertEquals(Decision.ALLOW,
                decide(session(OWNER, "Reader"), ALLOW_GET, policy, "s3:GetObject", BUCKET));
    }

    @Test
    void aResourcePolicyConditionIsEvaluatedLikeAnIdentityPolicyCondition() {
        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Principal":"*","Action":"s3:GetObject",
               "Resource":"arn:aws:s3:::owner-bucket/*",
               "Condition":{"StringEquals":{"aws:PrincipalAccount":"%s"}}}]}""".formatted(OWNER);
        CallerContext caller = CallerContext.of(List.of(NO_POLICY))
                .withPrincipal(session(OWNER, "Reader"));
        ResourcePolicies policies = ResourcePolicies.of(List.of(policy), OWNER);
        assertEquals(Decision.ALLOW, evaluator.evaluate(caller, policies, "s3:GetObject", BUCKET,
                Map.of("aws:PrincipalAccount", List.of(OWNER))));
        assertEquals(Decision.DENY, evaluator.evaluate(caller, policies, "s3:GetObject", BUCKET,
                Map.of("aws:PrincipalAccount", List.of(OTHER))));
    }

    // ── KMS: the key policy is the root of authority ───────────────────────────

    private static ResourcePolicies keyPolicy(String document) {
        return ResourcePolicies.keyPolicy(List.of(document), OWNER);
    }

    private static final String DEFAULT_KEY_POLICY = """
        {"Version":"2012-10-17","Statement":[
          {"Sid":"Enable IAM User Permissions","Effect":"Allow",
           "Principal":{"AWS":"arn:aws:iam::%s:root"},"Action":"kms:*","Resource":"*"}]}"""
            .formatted(OWNER);

    @Test
    void defaultKeyPolicyDelegatesToIdentityPoliciesInTheAccount() {
        assertEquals(Decision.ALLOW, decide(session(OWNER, "Administrator"), ALLOW_ALL,
                keyPolicy(DEFAULT_KEY_POLICY), "kms:Decrypt", KEY));
    }

    @Test
    void aKeyPolicyWithoutTheAccountDelegationRefusesTheAccountsAdministrator() {
        String noDelegation = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::%s:role/KeyUser"},
               "Action":"kms:Decrypt","Resource":"*"}]}""".formatted(OWNER);
        assertEquals(Decision.DENY, decide(session(OWNER, "Administrator"), ALLOW_ALL,
                keyPolicy(noDelegation), "kms:Decrypt", KEY));
        assertEquals(Decision.ALLOW, decide(session(OWNER, "KeyUser"), NO_POLICY,
                keyPolicy(noDelegation), "kms:Decrypt", KEY));
    }

    @Test
    void crossAccountKeyUseNeedsTheKeyPolicyAndTheIdentityPolicy() {
        String namesTheOtherAccount = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::%s:root"},
               "Action":"kms:*","Resource":"*"},
              {"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::%s:role/Reader"},
               "Action":"kms:Decrypt","Resource":"*"}]}""".formatted(OWNER, OTHER);
        assertEquals(Decision.DENY, decide(session(OTHER, "Reader"), NO_POLICY,
                keyPolicy(namesTheOtherAccount), "kms:Decrypt", KEY));
        assertEquals(Decision.ALLOW, decide(session(OTHER, "Reader"), ALLOW_ALL,
                keyPolicy(namesTheOtherAccount), "kms:Decrypt", KEY));
    }

    @Test
    void anExplicitDenyInAKeyPolicyRefusesTheAccountRootDelegation() {
        String withDeny = DEFAULT_KEY_POLICY.replace("]}", """
            ,{"Effect":"Deny","Principal":"*","Action":"kms:Decrypt","Resource":"*"}]}""");
        assertEquals(Decision.DENY, decide(session(OWNER, "Administrator"), ALLOW_ALL,
                keyPolicy(withDeny), "kms:Decrypt", KEY));
    }

    // ── Nothing changes where no resource policy is supplied ───────────────────

    @Test
    void withoutAResourcePolicyOnlyTheIdentityPolicyDecides() {
        assertEquals(Decision.ALLOW,
                decide(session(OWNER, "Reader"), ALLOW_GET, (ResourcePolicies) null,
                        "s3:GetObject", BUCKET));
        assertEquals(Decision.DENY,
                decide(session(OWNER, "Reader"), NO_POLICY, (ResourcePolicies) null,
                        "s3:GetObject", BUCKET));
    }

    @Test
    void anUnidentifiedPrincipalLeavesTheIdentityDecisionAlone() {
        CallerContext caller = CallerContext.of(List.of(ALLOW_GET));
        assertEquals(Decision.ALLOW,
                evaluator.evaluate(caller, null, "s3:GetObject", BUCKET, Map.of()));
    }
}

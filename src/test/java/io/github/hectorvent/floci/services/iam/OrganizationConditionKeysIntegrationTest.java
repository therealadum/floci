package io.github.hectorvent.floci.services.iam;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.restassured.RestAssured;
import io.restassured.config.EncoderConfig;
import io.restassured.config.RestAssuredConfig;
import io.restassured.http.ContentType;
import io.restassured.path.json.JsonPath;
import io.restassured.response.Response;
import io.restassured.response.ValidatableResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.startsWith;

/**
 * The organization and account condition keys, over the wire.
 *
 * <p>{@code aws:PrincipalOrgPaths}, {@code aws:PrincipalOrgID} and {@code aws:PrincipalAccount}
 * describe the caller and are populated for every request; {@code aws:ResourceOrgPaths},
 * {@code aws:ResourceOrgID} and {@code aws:ResourceAccount} describe the resource the request
 * names, and a request naming several resources carries one set per resource.
 *
 * <p>A path is AWS's own form, {@code o-<org>/r-<root>/ou-<ou>/.../<account>/}, trailing slash
 * included, which is what the Organizations API already reports as an OU's {@code Path} and as
 * the single entry of an account's {@code Paths}.
 */
@QuarkusTest
@TestProfile(OrganizationConditionKeysIntegrationTest.ConditionKeysProfile.class)
class OrganizationConditionKeysIntegrationTest {

    private static final String MGMT = "000000000000";
    private static final String STRANGER = "222222222222";
    private static final String REGION = "us-east-1";
    private static final String JSON_CONTENT_TYPE = "application/x-amz-json-1.1";
    private static final RestAssuredConfig JSON_1_1 = RestAssured.config()
            .encoderConfig(EncoderConfig.encoderConfig()
                    .encodeContentTypeAs(JSON_CONTENT_TYPE, ContentType.TEXT));

    private static String organizationId;
    private static String rootId;
    private static String unitId;
    private static String insideAccount;
    private static String outsideAccount;

    /** The path every account under the unit carries, as a {@code StringLike} pattern. */
    private static String unitPathPattern() {
        return organizationId + "/" + rootId + "/" + unitId + "/*";
    }

    /**
     * Creates the organization once for the class. It is not a {@code @BeforeAll}: RestAssured's
     * port is set per test method under {@code @QuarkusTest}, so a call made before the first one
     * reaches no server.
     */
    @BeforeEach
    void createOrganization() {
        if (organizationId != null) {
            return;
        }
        String suffix = suffix();
        org(MGMT, "CreateOrganization", "{\"FeatureSet\":\"ALL\"}").then().statusCode(200);
        organizationId = JsonPath.from(org(MGMT, "DescribeOrganization", "{}").asString())
                .getString("Organization.Id");
        rootId = JsonPath.from(org(MGMT, "ListRoots", "{}").asString()).getString("Roots[0].Id");
        unitId = JsonPath.from(org(MGMT, "CreateOrganizationalUnit",
                "{\"ParentId\":\"" + rootId + "\",\"Name\":\"Inside-" + suffix + "\"}").asString())
                .getString("OrganizationalUnit.Id");

        insideAccount = createMemberAccount("inside-" + suffix);
        org(MGMT, "MoveAccount",
                "{\"AccountId\":\"" + insideAccount + "\",\"SourceParentId\":\"" + rootId
                        + "\",\"DestinationParentId\":\"" + unitId + "\"}")
                .then().statusCode(200);
        outsideAccount = createMemberAccount("outside-" + suffix);
    }

    // ── aws:PrincipalOrgPaths ──────────────────────────────────────────────────

    @Test
    void aBucketPolicyOnPrincipalOrgPathsAdmitsTheUnitAndRefusesOutsideIt() {
        String suffix = suffix();
        String bucket = "org-paths-" + suffix;
        createBucket(MGMT, bucket);

        String insideSession = readerSession(insideAccount, "InsidePaths" + suffix, bucket);
        String outsideSession = readerSession(outsideAccount, "OutsidePaths" + suffix, bucket);

        putBucketPolicy(bucket, """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Principal":{"AWS":"*"},"Action":"s3:ListBucket",
               "Resource":"arn:aws:s3:::%s",
               "Condition":{"ForAnyValue:StringLike":{"aws:PrincipalOrgPaths":["%s"]}}}]}"""
                .formatted(bucket, unitPathPattern()));

        listBucket(bucket, insideSession).statusCode(200);
        listBucket(bucket, outsideSession).statusCode(403)
                .body(containsString("<Code>AccessDenied</Code>"));
    }

    // ── aws:PrincipalOrgID ─────────────────────────────────────────────────────

    @Test
    void aBucketPolicyOnPrincipalOrgIdAdmitsAMemberAndRefusesAnAccountOutsideTheOrganization() {
        String suffix = suffix();
        String bucket = "org-id-" + suffix;
        createBucket(MGMT, bucket);

        String memberSession = readerSession(insideAccount, "MemberOrgId" + suffix, bucket);
        String strangerSession = readerSession(STRANGER, "StrangerOrgId" + suffix, bucket);

        putBucketPolicy(bucket, """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Principal":{"AWS":"*"},"Action":"s3:ListBucket",
               "Resource":"arn:aws:s3:::%s",
               "Condition":{"StringEquals":{"aws:PrincipalOrgID":"%s"}}}]}"""
                .formatted(bucket, organizationId));

        listBucket(bucket, memberSession).statusCode(200);
        // An account in no organization carries none of the organization keys, as on AWS, so the
        // condition has nothing to match and the statement does not apply.
        listBucket(bucket, strangerSession).statusCode(403)
                .body(containsString("<Code>AccessDenied</Code>"));
    }

    // ── aws:ResourceAccount ────────────────────────────────────────────────────

    @Test
    void anIdentityPolicyOnResourceAccountMatchesTheAccountThatOwnsTheBucket() {
        String suffix = suffix();
        String bucket = "resource-account-" + suffix;
        String roleName = "ResourceAccountReader" + suffix;
        createBucket(insideAccount, bucket);
        createRole(insideAccount, roleName);

        putConditionalRolePolicy(insideAccount, roleName, "s3:ListBucket",
                "\"StringEquals\":{\"aws:ResourceAccount\":\"" + outsideAccount + "\"}");
        String session = assumeRole(insideAccount, roleName);
        listBucket(bucket, session).statusCode(403)
                .body(containsString("<Code>AccessDenied</Code>"));

        putConditionalRolePolicy(insideAccount, roleName, "s3:ListBucket",
                "\"StringEquals\":{\"aws:ResourceAccount\":\"" + insideAccount + "\"}");
        listBucket(bucket, assumeRole(insideAccount, roleName)).statusCode(200);
    }

    @Test
    void anIdentityPolicyOnResourceOrgPathsMatchesTheUnitTheResourcesAccountSitsIn() {
        String suffix = suffix();
        String bucket = "resource-paths-" + suffix;
        String roleName = "ResourcePathsReader" + suffix;
        createBucket(insideAccount, bucket);
        createRole(insideAccount, roleName);

        putConditionalRolePolicy(insideAccount, roleName, "s3:ListBucket",
                "\"ForAnyValue:StringLike\":{\"aws:ResourceOrgPaths\":[\"" + unitPathPattern() + "\"]}");
        listBucket(bucket, assumeRole(insideAccount, roleName)).statusCode(200);

        putConditionalRolePolicy(insideAccount, roleName, "s3:ListBucket",
                "\"ForAnyValue:StringLike\":{\"aws:ResourceOrgPaths\":[\""
                        + organizationId + "/" + rootId + "/ou-nowhere/*\"]}");
        listBucket(bucket, assumeRole(insideAccount, roleName)).statusCode(403)
                .body(containsString("<Code>AccessDenied</Code>"));
    }

    // ── aws:PrincipalAccount ───────────────────────────────────────────────────

    @Test
    void anIdentityPolicyOnPrincipalAccountMatchesTheAccountTheRoleBelongsTo() {
        String suffix = suffix();
        String bucket = "principal-account-" + suffix;
        String roleName = "PrincipalAccountReader" + suffix;
        createBucket(insideAccount, bucket);
        createRole(insideAccount, roleName);

        putConditionalRolePolicy(insideAccount, roleName, "s3:ListBucket",
                "\"StringEquals\":{\"aws:PrincipalAccount\":\"" + outsideAccount + "\"}");
        listBucket(bucket, assumeRole(insideAccount, roleName)).statusCode(403)
                .body(containsString("<Code>AccessDenied</Code>"));

        putConditionalRolePolicy(insideAccount, roleName, "s3:ListBucket",
                "\"StringEquals\":{\"aws:PrincipalAccount\":\"" + insideAccount + "\"}");
        listBucket(bucket, assumeRole(insideAccount, roleName)).statusCode(200);
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private static String suffix() {
        return UUID.randomUUID().toString().substring(0, 8);
    }

    private static String createMemberAccount(String name) {
        return JsonPath.from(org(MGMT, "CreateAccount",
                "{\"AccountName\":\"" + name + "\",\"Email\":\"" + name + "@floci.test\"}").asString())
                .getString("CreateAccountStatus.AccountId");
    }

    /** A role in {@code account} allowed to list {@code bucket}, assumed and returned as a key. */
    private static String readerSession(String account, String roleName, String bucket) {
        createRole(account, roleName);
        putRolePolicy(account, roleName, "s3:ListBucket", "arn:aws:s3:::" + bucket);
        return assumeRole(account, roleName);
    }

    private static void createBucket(String account, String bucket) {
        given().header("Authorization", auth(account, "s3"))
        .when().put("/" + bucket)
        .then().statusCode(200);
    }

    private static void putBucketPolicy(String bucket, String policy) {
        given().header("Authorization", auth(MGMT, "s3"))
                .contentType("application/json").body(policy)
        .when().put("/" + bucket + "?policy")
        .then().statusCode(200);
    }

    private static ValidatableResponse listBucket(String bucket, String accessKeyId) {
        return given().header("Authorization", auth(accessKeyId, "s3"))
                .queryParam("list-type", "2")
                .when().get("/" + bucket)
                .then();
    }

    private static void createRole(String account, String roleName) {
        given().formParam("Action", "CreateRole")
                .formParam("RoleName", roleName)
                .formParam("Path", "/")
                .formParam("AssumeRolePolicyDocument", """
                    {"Version":"2012-10-17","Statement":[
                      {"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}""")
                .header("Authorization", auth(account, "iam"))
        .when().post("/")
        .then().statusCode(200);
    }

    private static void putRolePolicy(String account, String roleName, String action, String resource) {
        putRolePolicyDocument(account, roleName, """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"%s","Resource":"%s"}]}""".formatted(action, resource));
    }

    private static void putConditionalRolePolicy(String account, String roleName, String action,
                                                 String condition) {
        putRolePolicyDocument(account, roleName, """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"%s","Resource":"*","Condition":{%s}}]}"""
                .formatted(action, condition));
    }

    private static void putRolePolicyDocument(String account, String roleName, String document) {
        given().formParam("Action", "PutRolePolicy")
                .formParam("RoleName", roleName)
                .formParam("PolicyName", "ConditionKeys")
                .formParam("PolicyDocument", document)
                .header("Authorization", auth(account, "iam"))
        .when().post("/")
        .then().statusCode(200);
    }

    private static String assumeRole(String account, String roleName) {
        return given().formParam("Action", "AssumeRole")
                .formParam("RoleArn", "arn:aws:iam::" + account + ":role/" + roleName)
                .formParam("RoleSessionName", "condition-keys-test")
                .header("Authorization", auth(account, "sts"))
        .when().post("/")
        .then().statusCode(200)
                .body("AssumeRoleResponse.AssumeRoleResult.Credentials.AccessKeyId", startsWith("ASIA"))
                .extract().path("AssumeRoleResponse.AssumeRoleResult.Credentials.AccessKeyId");
    }

    private static Response org(String account, String action, String body) {
        return given().config(JSON_1_1)
                .header("Authorization", auth(account, "organizations"))
                .header("X-Amz-Target", "AWSOrganizationsV20161128." + action)
                .contentType(JSON_CONTENT_TYPE)
                .body(body)
                .when().post("/");
    }

    private static String auth(String accessKeyId, String service) {
        return "AWS4-HMAC-SHA256 Credential=" + accessKeyId + "/20260629/" + REGION + "/" + service
                + "/aws4_request, SignedHeaders=host, Signature=abc";
    }

    public static final class ConditionKeysProfile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of(
                    "floci.services.iam.enforcement-enabled", "true",
                    "floci.services.s3.global-bucket-namespace", "true");
        }
    }
}

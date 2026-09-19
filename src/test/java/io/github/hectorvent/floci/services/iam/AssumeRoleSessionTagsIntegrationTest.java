package io.github.hectorvent.floci.services.iam;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.restassured.path.xml.XmlPath;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.UUID;

import static io.restassured.RestAssured.given;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * What {@code AssumeRole} does with {@code ExternalId}, {@code Tags} and {@code TransitiveTagKeys}.
 *
 * <ul>
 *   <li>A trust policy requiring {@code sts:ExternalId} refuses a call that carries none, and one
 *       carrying the wrong value.</li>
 *   <li>Passing {@code Tags} needs {@code sts:TagSession} allowed by the trust policy, which sees
 *       the tags as {@code aws:RequestTag/<key>} and {@code aws:TagKeys}.</li>
 *   <li>The session's tags are {@code aws:PrincipalTag/<key>} on every request it then makes.</li>
 *   <li>A transitive tag key carries into the next role the session assumes.</li>
 * </ul>
 */
@QuarkusTest
@TestProfile(AssumeRoleSessionTagsIntegrationTest.SessionTagProfile.class)
class AssumeRoleSessionTagsIntegrationTest {

    private static final String ACCOUNT = "550000000001";
    private static final String EXTERNAL_ID = "mycellium-drata-1234";

    private static String suffix;
    private static String bucket;

    @BeforeEach
    void createTheRoles() {
        if (suffix != null) {
            return;
        }
        suffix = UUID.randomUUID().toString().substring(0, 8);
        bucket = "session-tags-" + suffix;

        // A role Drata's shape: the external id is the trust policy's condition, so a call
        // without it is refused whatever else it carries.
        createRole("Audit" + suffix, """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::%s:root"},"Action":"sts:AssumeRole",
               "Condition":{"StringEquals":{"sts:ExternalId":"%s"}}}]}"""
                .formatted(ACCOUNT, EXTERNAL_ID));

        // A role that may be assumed by anyone in the account but tagged by nobody.
        createRole("Untagged" + suffix, """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::%s:root"},"Action":"sts:AssumeRole"}]}"""
                .formatted(ACCOUNT));

        // A role that may be tagged, with the tag keys the trust policy names and no others, and
        // whose own permissions are gated on the tag the session carries.
        createRole("Tenant" + suffix, """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::%s:root"},
               "Action":["sts:AssumeRole","sts:TagSession"],
               "Condition":{"ForAllValues:StringEquals":{"aws:TagKeys":["tenant"]}}}]}"""
                .formatted(ACCOUNT));
        putRolePolicy("Tenant" + suffix, "tenant-bucket", """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"s3:*","Resource":"*",
               "Condition":{"StringEquals":{"aws:PrincipalTag/tenant":"alpha"}}},
              {"Effect":"Allow","Action":"sts:AssumeRole",
               "Resource":"arn:aws:iam::%s:role/Downstream%s"}]}"""
                .formatted(ACCOUNT, suffix));

        // A second role, trusted by the first, for the transitive carry.
        createRole("Downstream" + suffix, """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::%s:role/Tenant%s"},
               "Action":"sts:AssumeRole"}]}"""
                .formatted(ACCOUNT, suffix));
        putRolePolicy("Downstream" + suffix, "tenant-bucket", """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"s3:*","Resource":"*",
               "Condition":{"StringEquals":{"aws:PrincipalTag/tenant":"alpha"}}}]}""");

        given().header("Authorization", auth(ACCOUNT, "s3"))
                .when().put("/" + bucket).then().statusCode(200);
    }

    @Test
    void aTrustPolicyRequiringAnExternalIdRefusesACallWithoutIt() {
        assumeRole("Audit" + suffix, Map.of()).then().statusCode(403);
        assumeRole("Audit" + suffix, Map.of("ExternalId", "wrong")).then().statusCode(403);
        assumeRole("Audit" + suffix, Map.of("ExternalId", EXTERNAL_ID)).then().statusCode(200);
    }

    @Test
    void taggingASessionNeedsTagSessionAllowedByTheTrustPolicy() {
        // The role may be assumed, so the untagged call succeeds.
        assumeRole("Untagged" + suffix, Map.of()).then().statusCode(200);
        // The same call carrying tags is refused: nothing allows sts:TagSession.
        assumeRole("Untagged" + suffix, Map.of(
                "Tags.member.1.Key", "tenant", "Tags.member.1.Value", "alpha"))
                .then().statusCode(403);
    }

    @Test
    void theTrustPolicySeesTheTagKeysTheRequestCarries() {
        assumeRole("Tenant" + suffix, Map.of(
                "Tags.member.1.Key", "tenant", "Tags.member.1.Value", "alpha"))
                .then().statusCode(200);
        // aws:TagKeys names "tenant" alone, so a second key the policy does not name is refused.
        assumeRole("Tenant" + suffix, Map.of(
                "Tags.member.1.Key", "tenant", "Tags.member.1.Value", "alpha",
                "Tags.member.2.Key", "environment", "Tags.member.2.Value", "stage"))
                .then().statusCode(403);
    }

    @Test
    void theSessionsTagsArePrincipalTagOnItsOwnRequests() {
        String allowed = accessKeyOf(assumeRole("Tenant" + suffix, Map.of(
                "Tags.member.1.Key", "tenant", "Tags.member.1.Value", "alpha")));
        String refused = accessKeyOf(assumeRole("Tenant" + suffix, Map.of(
                "Tags.member.1.Key", "tenant", "Tags.member.1.Value", "beta")));

        listBucket(allowed).then().statusCode(200);
        listBucket(refused).then().statusCode(403);
    }

    @Test
    void aTransitiveTagKeyCarriesIntoTheNextRole() {
        String tagged = accessKeyOf(assumeRole("Tenant" + suffix, Map.of(
                "Tags.member.1.Key", "tenant", "Tags.member.1.Value", "alpha",
                "TransitiveTagKeys.member.1", "tenant")));
        String notTransitive = accessKeyOf(assumeRole("Tenant" + suffix, Map.of(
                "Tags.member.1.Key", "tenant", "Tags.member.1.Value", "alpha")));

        String carried = accessKeyOf(assumeRoleAs("Downstream" + suffix, tagged, Map.of()));
        listBucket(carried).then().statusCode(200);

        String dropped = accessKeyOf(assumeRoleAs("Downstream" + suffix, notTransitive, Map.of()));
        listBucket(dropped).then().statusCode(403);
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private Response assumeRole(String roleName, Map<String, String> extra) {
        return assumeRoleAs(roleName, ACCOUNT, extra);
    }

    private Response assumeRoleAs(String roleName, String accessKeyId, Map<String, String> extra) {
        RequestSpecification request = given()
                .header("Authorization", auth(accessKeyId, "sts"))
                .formParam("Action", "AssumeRole")
                .formParam("RoleArn", "arn:aws:iam::" + ACCOUNT + ":role/" + roleName)
                .formParam("RoleSessionName", "session-" + suffix);
        for (Map.Entry<String, String> entry : extra.entrySet()) {
            request = request.formParam(entry.getKey(), entry.getValue());
        }
        return request.when().post("/");
    }

    private static String accessKeyOf(Response response) {
        response.then().statusCode(200);
        String accessKeyId = XmlPath.from(response.asString())
                .getString("AssumeRoleResponse.AssumeRoleResult.Credentials.AccessKeyId");
        assertNotNull(accessKeyId);
        return accessKeyId;
    }

    private Response listBucket(String accessKeyId) {
        return given().header("Authorization", auth(accessKeyId, "s3"))
                .queryParam("list-type", "2")
                .when().get("/" + bucket);
    }

    private static void createRole(String roleName, String trustPolicy) {
        given().header("Authorization", auth(ACCOUNT, "iam"))
                .formParam("Action", "CreateRole")
                .formParam("RoleName", roleName)
                .formParam("Path", "/")
                .formParam("AssumeRolePolicyDocument", trustPolicy)
                .when().post("/")
                .then().statusCode(200);
    }

    private static void putRolePolicy(String roleName, String policyName, String document) {
        given().header("Authorization", auth(ACCOUNT, "iam"))
                .formParam("Action", "PutRolePolicy")
                .formParam("RoleName", roleName)
                .formParam("PolicyName", policyName)
                .formParam("PolicyDocument", document)
                .when().post("/")
                .then().statusCode(200);
    }

    private static String auth(String accessKeyId, String service) {
        return "AWS4-HMAC-SHA256 Credential=" + accessKeyId
                + "/20260918/us-east-1/" + service + "/aws4_request, SignedHeaders=host, Signature=abc";
    }

    public static final class SessionTagProfile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of(
                    "floci.services.iam.enforcement-enabled", "true",
                    "floci.services.s3.global-bucket-namespace", "true");
        }
    }
}

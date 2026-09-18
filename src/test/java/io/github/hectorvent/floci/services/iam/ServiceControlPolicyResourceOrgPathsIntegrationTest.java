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
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;

/**
 * Section 6's other half: a service control policy on a unit denies its members reaching out past
 * the unit's organization path. The policy denies everything whose {@code aws:ResourceOrgPaths}
 * is outside the unit, so a member reaching a bucket in another unit is refused and the same
 * member reaching a bucket inside its own unit is not.
 */
@QuarkusTest
@TestProfile(ServiceControlPolicyResourceOrgPathsIntegrationTest.ScpEnforcementProfile.class)
class ServiceControlPolicyResourceOrgPathsIntegrationTest {

    private static final String MGMT = "000000000000";
    private static final String REGION = "us-east-1";
    private static final String JSON_CONTENT_TYPE = "application/x-amz-json-1.1";
    private static final RestAssuredConfig JSON_1_1 = RestAssured.config()
            .encoderConfig(EncoderConfig.encoderConfig()
                    .encodeContentTypeAs(JSON_CONTENT_TYPE, ContentType.TEXT));

    @Test
    void aUnitsServiceControlPolicyRefusesItsMemberReachingABucketInAnotherUnit() {
        String suffix = UUID.randomUUID().toString().substring(0, 8);

        org(MGMT, "CreateOrganization", "{\"FeatureSet\":\"ALL\"}").then().statusCode(200);
        String organizationId = JsonPath.from(org(MGMT, "DescribeOrganization", "{}").asString())
                .getString("Organization.Id");
        String rootId = JsonPath.from(org(MGMT, "ListRoots", "{}").asString()).getString("Roots[0].Id");
        org(MGMT, "EnablePolicyType",
                "{\"RootId\":\"" + rootId + "\",\"PolicyType\":\"SERVICE_CONTROL_POLICY\"}")
                .then().statusCode(200);

        String homeUnit = createUnit(rootId, "Home-" + suffix);
        String otherUnit = createUnit(rootId, "Other-" + suffix);
        String member = createMemberAccountIn(homeUnit, rootId, "member-" + suffix);
        String neighbour = createMemberAccountIn(otherUnit, rootId, "neighbour-" + suffix);

        String homeBucket = "scp-home-" + suffix;
        createBucket(member, homeBucket);
        String otherBucket = "scp-other-" + suffix;
        createBucket(neighbour, otherBucket);
        putBucketPolicy(neighbour, otherBucket, """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Principal":{"AWS":"*"},"Action":"s3:ListBucket",
               "Resource":"arn:aws:s3:::%s"}]}""".formatted(otherBucket));

        // Before the policy, the member reaches both buckets.
        listBucket(homeBucket, member).statusCode(200);
        listBucket(otherBucket, member).statusCode(200);

        String policyId = JsonPath.from(org(MGMT, "CreatePolicy",
                "{\"Name\":\"deny-outward-" + suffix + "\",\"Type\":\"SERVICE_CONTROL_POLICY\","
                        + "\"Description\":\"deny reaching out past the unit\",\"Content\":"
                        + jsonString("""
                        {"Version":"2012-10-17","Statement":[
                          {"Sid":"DenyReachingOut","Effect":"Deny","Action":"*","Resource":"*",
                           "Condition":{"StringNotLike":{"aws:ResourceOrgPaths":"%s/%s/%s/*"}}}]}"""
                        .formatted(organizationId, rootId, homeUnit)) + "}").asString())
                .getString("Policy.PolicySummary.Id");
        org(MGMT, "AttachPolicy",
                "{\"PolicyId\":\"" + policyId + "\",\"TargetId\":\"" + homeUnit + "\"}")
                .then().statusCode(200);

        listBucket(otherBucket, member).statusCode(403)
                .body(containsString("<Code>AccessDenied</Code>"));
        listBucket(homeBucket, member).statusCode(200);
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private static String createUnit(String rootId, String name) {
        return JsonPath.from(org(MGMT, "CreateOrganizationalUnit",
                "{\"ParentId\":\"" + rootId + "\",\"Name\":\"" + name + "\"}").asString())
                .getString("OrganizationalUnit.Id");
    }

    private static String createMemberAccountIn(String unitId, String rootId, String name) {
        String accountId = JsonPath.from(org(MGMT, "CreateAccount",
                "{\"AccountName\":\"" + name + "\",\"Email\":\"" + name + "@floci.test\"}").asString())
                .getString("CreateAccountStatus.AccountId");
        org(MGMT, "MoveAccount",
                "{\"AccountId\":\"" + accountId + "\",\"SourceParentId\":\"" + rootId
                        + "\",\"DestinationParentId\":\"" + unitId + "\"}")
                .then().statusCode(200);
        return accountId;
    }

    private static void createBucket(String account, String bucketName) {
        given().header("Authorization", auth(account, "s3"))
        .when().put("/" + bucketName)
        .then().statusCode(200);
    }

    private static void putBucketPolicy(String account, String bucketName, String policy) {
        given().header("Authorization", auth(account, "s3"))
                .contentType("application/json").body(policy)
        .when().put("/" + bucketName + "?policy")
        .then().statusCode(200);
    }

    private static ValidatableResponse listBucket(String bucketName, String accessKeyId) {
        return given().header("Authorization", auth(accessKeyId, "s3"))
                .queryParam("list-type", "2")
                .when().get("/" + bucketName)
                .then();
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

    private static String jsonString(String value) {
        StringBuilder out = new StringBuilder("\"");
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> out.append(c);
            }
        }
        return out.append('"').toString();
    }

    public static final class ScpEnforcementProfile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of(
                    "floci.services.iam.enforcement-enabled", "true",
                    "floci.services.organizations.scp-enforcement-enabled", "true",
                    "floci.services.s3.global-bucket-namespace", "true");
        }
    }
}

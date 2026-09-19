package io.github.hectorvent.floci.services.iam;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.restassured.RestAssured;
import io.restassured.config.EncoderConfig;
import io.restassured.config.RestAssuredConfig;
import io.restassured.http.ContentType;
import io.restassured.path.json.JsonPath;
import io.restassured.path.xml.XmlPath;
import io.restassured.response.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.UUID;

import static io.restassured.RestAssured.given;

/**
 * The principal condition keys inside organization policies.
 *
 * <ul>
 *   <li>A service control policy can spare one named role and refuse every other principal, which
 *       is how the installer and the entry role keep what the rest of an account may not do.</li>
 *   <li>{@code aws:PrincipalIsAWSService} is false for a principal that signs a request.</li>
 *   <li>{@code aws:SourceOrgID} and {@code aws:SourceOrgPaths} are absent when no service calls on
 *       a resource's behalf, so a {@code Null} guard on them reads as AWS's does.</li>
 * </ul>
 */
@QuarkusTest
@TestProfile(OrganizationPolicyPrincipalKeysIntegrationTest.OrganizationPolicyProfile.class)
class OrganizationPolicyPrincipalKeysIntegrationTest {

    private static final String MANAGEMENT = "560000000001";
    private static final String JSON_CONTENT_TYPE = "application/x-amz-json-1.1";
    private static final RestAssuredConfig JSON_1_1 = RestAssured.config()
            .encoderConfig(EncoderConfig.encoderConfig()
                    .encodeContentTypeAs(JSON_CONTENT_TYPE, ContentType.TEXT));

    private static String suffix;

    @BeforeEach
    void createTheOrganization() {
        if (suffix != null) {
            return;
        }
        suffix = UUID.randomUUID().toString().substring(0, 8);
        organizations("CreateOrganization", "{\"FeatureSet\":\"ALL\"}").then().statusCode(200);
        String rootId = JsonPath.from(organizations("ListRoots", "{}").asString())
                .getString("Roots[0].Id");
        organizations("EnablePolicyType",
                "{\"RootId\":\"" + rootId + "\",\"PolicyType\":\"SERVICE_CONTROL_POLICY\"}")
                .then().statusCode(200);
        organizations("EnablePolicyType",
                "{\"RootId\":\"" + rootId + "\",\"PolicyType\":\"RESOURCE_CONTROL_POLICY\"}")
                .then().statusCode(200);
    }

    @Test
    void aServiceControlPolicySparesTheRoleItNames() {
        String account = memberAccount("spare");
        String bucket = createBucket(account, "spare");
        String installer = assumableRole(account, "Installer" + suffix);
        String ordinary = assumableRole(account, "Ordinary" + suffix);

        attach(account, "SERVICE_CONTROL_POLICY", "spare-the-installer", """
            {"Version":"2012-10-17","Statement":[
              {"Sid":"OnlyTheInstaller","Effect":"Deny","Action":"s3:*","Resource":"*",
               "Condition":{"StringNotLike":
                 {"aws:PrincipalArn":"arn:aws:sts::*:assumed-role/Installer%s/*"}}}]}"""
                .formatted(suffix));

        listBucket(bucket, assume(account, installer)).then().statusCode(200);
        listBucket(bucket, assume(account, ordinary)).then().statusCode(403);
    }

    @Test
    void aPrincipalThatSignsARequestIsNotAnAwsService() {
        String account = memberAccount("service");
        String bucket = createBucket(account, "service");

        attach(account, "RESOURCE_CONTROL_POLICY", "deny-aws-services", """
            {"Version":"2012-10-17","Statement":[
              {"Sid":"DenyServices","Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"*",
               "Condition":{"Bool":{"aws:PrincipalIsAWSService":"true"}}}]}""");
        listBucket(bucket, account).then().statusCode(200);

        attach(account, "RESOURCE_CONTROL_POLICY", "deny-everyone-else", """
            {"Version":"2012-10-17","Statement":[
              {"Sid":"DenyNonServices","Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"*",
               "Condition":{"Bool":{"aws:PrincipalIsAWSService":"false"}}}]}""");
        listBucket(bucket, account).then().statusCode(403);
    }

    @Test
    void theSourceOrganizationKeysAreAbsentWhenNoServiceCallsOnAResourcesBehalf() {
        String account = memberAccount("source");
        String bucket = createBucket(account, "source");

        attach(account, "RESOURCE_CONTROL_POLICY", "deny-when-source-present", """
            {"Version":"2012-10-17","Statement":[
              {"Sid":"DenyWhenPresent","Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"*",
               "Condition":{"Null":{"aws:SourceOrgID":"false","aws:SourceOrgPaths":"false"}}}]}""");
        listBucket(bucket, account).then().statusCode(200);

        attach(account, "RESOURCE_CONTROL_POLICY", "deny-when-source-absent", """
            {"Version":"2012-10-17","Statement":[
              {"Sid":"DenyWhenAbsent","Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"*",
               "Condition":{"Null":{"aws:SourceOrgID":"true","aws:SourceOrgPaths":"true"}}}]}""");
        listBucket(bucket, account).then().statusCode(403);
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private String memberAccount(String name) {
        String accountName = name + "-" + suffix;
        return JsonPath.from(organizations("CreateAccount",
                "{\"AccountName\":\"" + accountName + "\",\"Email\":\"" + accountName + "@floci.test\"}")
                .asString()).getString("CreateAccountStatus.AccountId");
    }

    private void attach(String targetId, String type, String name, String content) {
        String policyId = JsonPath.from(organizations("CreatePolicy",
                jsonObject(Map.of("Name", name + "-" + targetId, "Type", type,
                        "Description", name, "Content", content))).asString())
                .getString("Policy.PolicySummary.Id");
        organizations("AttachPolicy",
                "{\"PolicyId\":\"" + policyId + "\",\"TargetId\":\"" + targetId + "\"}")
                .then().statusCode(200);
    }

    /** A role in {@code account} that the account's root may assume and that may reach S3. */
    private String assumableRole(String account, String roleName) {
        given().header("Authorization", auth(account, "iam"))
                .formParam("Action", "CreateRole")
                .formParam("RoleName", roleName)
                .formParam("Path", "/")
                .formParam("AssumeRolePolicyDocument", """
                    {"Version":"2012-10-17","Statement":[
                      {"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::%s:root"},
                       "Action":"sts:AssumeRole"}]}""".formatted(account))
                .when().post("/").then().statusCode(200);
        given().header("Authorization", auth(account, "iam"))
                .formParam("Action", "PutRolePolicy")
                .formParam("RoleName", roleName)
                .formParam("PolicyName", "everything")
                .formParam("PolicyDocument",
                        "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\","
                                + "\"Action\":\"*\",\"Resource\":\"*\"}]}")
                .when().post("/").then().statusCode(200);
        return "arn:aws:iam::" + account + ":role/" + roleName;
    }

    private String assume(String account, String roleArn) {
        Response response = given().header("Authorization", auth(account, "sts"))
                .formParam("Action", "AssumeRole")
                .formParam("RoleArn", roleArn)
                .formParam("RoleSessionName", "principal-keys")
                .when().post("/");
        response.then().statusCode(200);
        return XmlPath.from(response.asString())
                .getString("AssumeRoleResponse.AssumeRoleResult.Credentials.AccessKeyId");
    }

    private String createBucket(String account, String name) {
        String bucket = "principal-keys-" + name + "-" + suffix;
        given().header("Authorization", auth(account, "s3"))
                .when().put("/" + bucket).then().statusCode(200);
        return bucket;
    }

    private Response listBucket(String bucket, String accessKeyId) {
        return given().header("Authorization", auth(accessKeyId, "s3"))
                .queryParam("list-type", "2")
                .when().get("/" + bucket);
    }

    private static Response organizations(String action, String body) {
        return given().config(JSON_1_1)
                .header("Authorization", auth(MANAGEMENT, "organizations"))
                .header("X-Amz-Target", "AWSOrganizationsV20161128." + action)
                .contentType(JSON_CONTENT_TYPE)
                .body(body)
                .when().post("/");
    }

    private static String auth(String accessKeyId, String service) {
        return "AWS4-HMAC-SHA256 Credential=" + accessKeyId
                + "/20260918/us-east-1/" + service + "/aws4_request, SignedHeaders=host, Signature=abc";
    }

    private static String jsonObject(Map<String, String> fields) {
        StringBuilder out = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, String> field : fields.entrySet()) {
            if (!first) {
                out.append(',');
            }
            first = false;
            out.append(jsonString(field.getKey())).append(':').append(jsonString(field.getValue()));
        }
        return out.append('}').toString();
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

    public static final class OrganizationPolicyProfile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of(
                    "floci.services.iam.enforcement-enabled", "true",
                    "floci.services.organizations.scp-enforcement-enabled", "true",
                    "floci.services.s3.global-bucket-namespace", "true");
        }
    }
}

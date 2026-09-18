package io.github.hectorvent.floci.services.iam;

import io.restassured.RestAssured;
import io.restassured.config.EncoderConfig;
import io.restassured.config.RestAssuredConfig;
import io.restassured.http.ContentType;
import io.restassured.path.json.JsonPath;
import io.restassured.response.Response;
import io.restassured.response.ValidatableResponse;

import java.util.Map;
import java.util.UUID;

import static io.restassured.RestAssured.given;

/**
 * The organization a resource control policy test works against: a unit holding one member
 * account, a second member account outside it, and, in the account inside the unit, a bucket, a
 * secret and a role every principal is already allowed to reach. What the policy then refuses is
 * the organization path of the caller and nothing else.
 *
 * <p>Shared by the enforcement test and the flag-off test, which differ only in their profile.
 */
final class ResourceControlPolicyFixture {

    private static final String MGMT = "000000000000";
    private static final String REGION = "us-east-1";
    private static final String JSON_CONTENT_TYPE = "application/x-amz-json-1.1";
    private static final RestAssuredConfig JSON_1_1 = RestAssured.config()
            .encoderConfig(EncoderConfig.encoderConfig()
                    .encodeContentTypeAs(JSON_CONTENT_TYPE, ContentType.TEXT));

    private final String organizationId;
    private final String rootId;
    private final String unitId;
    private final String insideAccount;
    private final String outsideAccount;
    private final String bucket;
    private final String managementBucket;
    private final String secretArn;
    private final String roleArn;

    private ResourceControlPolicyFixture(String organizationId, String rootId, String unitId,
                                         String insideAccount, String outsideAccount,
                                         String bucket, String managementBucket,
                                         String secretArn, String roleArn) {
        this.organizationId = organizationId;
        this.rootId = rootId;
        this.unitId = unitId;
        this.insideAccount = insideAccount;
        this.outsideAccount = outsideAccount;
        this.bucket = bucket;
        this.managementBucket = managementBucket;
        this.secretArn = secretArn;
        this.roleArn = roleArn;
    }

    static ResourceControlPolicyFixture create() {
        String suffix = UUID.randomUUID().toString().substring(0, 8);

        org(MGMT, "CreateOrganization", "{\"FeatureSet\":\"ALL\"}").then().statusCode(200);
        String organizationId = JsonPath.from(org(MGMT, "DescribeOrganization", "{}").asString())
                .getString("Organization.Id");
        String rootId = JsonPath.from(org(MGMT, "ListRoots", "{}").asString()).getString("Roots[0].Id");

        // Enabling the type first is what attaches RCPFullAWSAccess to the root, and to every unit
        // and account created after it, exactly as AWS does.
        org(MGMT, "EnablePolicyType",
                "{\"RootId\":\"" + rootId + "\",\"PolicyType\":\"RESOURCE_CONTROL_POLICY\"}")
                .then().statusCode(200);

        String unitId = JsonPath.from(org(MGMT, "CreateOrganizationalUnit",
                "{\"ParentId\":\"" + rootId + "\",\"Name\":\"Inside-" + suffix + "\"}").asString())
                .getString("OrganizationalUnit.Id");

        String insideAccount = createMemberAccount("inside-" + suffix);
        org(MGMT, "MoveAccount",
                "{\"AccountId\":\"" + insideAccount + "\",\"SourceParentId\":\"" + rootId
                        + "\",\"DestinationParentId\":\"" + unitId + "\"}")
                .then().statusCode(200);
        String outsideAccount = createMemberAccount("outside-" + suffix);

        String bucket = "rcp-inside-" + suffix;
        createBucket(insideAccount, bucket);
        putBucketPolicy(insideAccount, bucket, """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Principal":{"AWS":"*"},"Action":"s3:ListBucket",
               "Resource":"arn:aws:s3:::%s"}]}""".formatted(bucket));

        String managementBucket = "rcp-management-" + suffix;
        createBucket(MGMT, managementBucket);
        putBucketPolicy(MGMT, managementBucket, """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Principal":{"AWS":"*"},"Action":"s3:ListBucket",
               "Resource":"arn:aws:s3:::%s"}]}""".formatted(managementBucket));

        String secretArn = createSecret(insideAccount, "rcp-secret-" + suffix);
        putSecretResourcePolicy(insideAccount, secretArn, """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Principal":{"AWS":"*"},
               "Action":"secretsmanager:GetSecretValue","Resource":"*"}]}""");

        String roleName = "RcpTarget" + suffix;
        createRole(insideAccount, roleName);
        String roleArn = "arn:aws:iam::" + insideAccount + ":role/" + roleName;

        return new ResourceControlPolicyFixture(organizationId, rootId, unitId, insideAccount,
                outsideAccount, bucket, managementBucket, secretArn, roleArn);
    }

    /**
     * Attaches to the unit a resource control policy denying every principal whose organization
     * path is not under it. A resource control policy never grants: this one only takes away, and
     * the RCPFullAWSAccess the enabled type attached is what keeps everything else reachable.
     */
    void attachDenyOutsideTheUnit() {
        String policyId = JsonPath.from(org(MGMT, "CreatePolicy",
                "{\"Name\":\"deny-outside-" + unitId + "\",\"Type\":\"RESOURCE_CONTROL_POLICY\","
                        + "\"Description\":\"deny reaching in from outside the unit\",\"Content\":"
                        + jsonString("""
                        {"Version":"2012-10-17","Statement":[
                          {"Sid":"DenyOutsideTheUnit","Effect":"Deny","Principal":"*",
                           "Action":"*","Resource":"*",
                           "Condition":{"StringNotLike":{"aws:PrincipalOrgPaths":"%s/%s/%s/*"}}}]}"""
                        .formatted(organizationId, rootId, unitId)) + "}").asString())
                .getString("Policy.PolicySummary.Id");

        org(MGMT, "AttachPolicy",
                "{\"PolicyId\":\"" + policyId + "\",\"TargetId\":\"" + unitId + "\"}")
                .then().statusCode(200);
    }

    String insideAccount() {
        return insideAccount;
    }

    String outsideAccount() {
        return outsideAccount;
    }

    String bucket() {
        return bucket;
    }

    String managementBucket() {
        return managementBucket;
    }

    String secretArn() {
        return secretArn;
    }

    String roleArn() {
        return roleArn;
    }

    ValidatableResponse listBucket(String bucketName, String accessKeyId) {
        return given().header("Authorization", auth(accessKeyId, "s3"))
                .queryParam("list-type", "2")
                .when().get("/" + bucketName)
                .then();
    }

    ValidatableResponse getSecretValue(String secretId, String accessKeyId) {
        return given().config(JSON_1_1)
                .header("Authorization", auth(accessKeyId, "secretsmanager"))
                .header("X-Amz-Target", "secretsmanager.GetSecretValue")
                .contentType(JSON_CONTENT_TYPE)
                .body(jsonObject(Map.of("SecretId", secretId)))
                .when().post("/")
                .then();
    }

    ValidatableResponse assumeRole(String targetRoleArn, String accessKeyId) {
        return given().formParam("Action", "AssumeRole")
                .formParam("RoleArn", targetRoleArn)
                .formParam("RoleSessionName", "rcp-test")
                .header("Authorization", auth(accessKeyId, "sts"))
                .when().post("/")
                .then();
    }

    // ── Setup helpers ──────────────────────────────────────────────────────────

    private static String createMemberAccount(String name) {
        return JsonPath.from(org(MGMT, "CreateAccount",
                "{\"AccountName\":\"" + name + "\",\"Email\":\"" + name + "@floci.test\"}").asString())
                .getString("CreateAccountStatus.AccountId");
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

    private static String createSecret(String account, String name) {
        return given().config(JSON_1_1)
                .header("Authorization", auth(account, "secretsmanager"))
                .header("X-Amz-Target", "secretsmanager.CreateSecret")
                .contentType(JSON_CONTENT_TYPE)
                .body("{\"Name\":\"" + name + "\",\"SecretString\":\"s3cret\"}")
        .when().post("/")
        .then().statusCode(200)
                .extract().path("ARN");
    }

    private static void putSecretResourcePolicy(String account, String secretId, String policy) {
        given().config(JSON_1_1)
                .header("Authorization", auth(account, "secretsmanager"))
                .header("X-Amz-Target", "secretsmanager.PutResourcePolicy")
                .contentType(JSON_CONTENT_TYPE)
                .body(jsonObject(Map.of("SecretId", secretId, "ResourcePolicy", policy)))
        .when().post("/")
        .then().statusCode(200);
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

    /** Minimal JSON object writer: every value here is a plain string, policies among them. */
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
}

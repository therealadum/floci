package io.github.hectorvent.floci.services.iam;

import io.restassured.RestAssured;
import io.restassured.config.EncoderConfig;
import io.restassured.config.RestAssuredConfig;
import io.restassured.http.ContentType;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.startsWith;

/**
 * Resource policies reaching the one evaluator over the wire: a bucket policy, a key policy and
 * a secret's resource policy are evaluated beside the caller's identity policies, with AWS's
 * cross-account meaning.
 */
@QuarkusTest
@TestProfile(ResourcePolicyEnforcementIntegrationTest.ResourcePolicyProfile.class)
class ResourcePolicyEnforcementIntegrationTest {

    private static final String OWNER_ACCOUNT = "111111111111";
    private static final String CALLER_ACCOUNT = "222222222222";
    private static final String REGION = "us-east-1";
    private static final String JSON_CONTENT_TYPE = "application/x-amz-json-1.1";
    /** RestAssured has no encoder for the JSON 1.1 content type; tell it the body is text. */
    private static final RestAssuredConfig JSON_1_1 = RestAssured.config()
            .encoderConfig(EncoderConfig.encoderConfig()
                    .encodeContentTypeAs(JSON_CONTENT_TYPE, ContentType.TEXT));

    // ── Buckets ────────────────────────────────────────────────────────────────

    @Test
    void crossAccountBucketReadNeedsTheBucketPolicyAndTheRolePolicy() {
        String suffix = suffix();
        String bucket = "cross-account-" + suffix;
        String roleName = "CrossReader" + suffix;
        createBucket(bucket);
        putObject(bucket, "file.txt");
        createRole(roleName);
        putRolePolicy(roleName, "s3:ListBucket", "arn:aws:s3:::" + bucket);
        String sessionKey = assumeRole(roleName);

        // The role's own policy allows, but no bucket policy names it.
        listBucket(bucket, sessionKey).statusCode(403)
                .body(containsString("<Code>AccessDenied</Code>"));

        putBucketPolicy(bucket, """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::%s:role/%s"},
               "Action":"s3:ListBucket","Resource":"arn:aws:s3:::%s"}]}"""
                .formatted(CALLER_ACCOUNT, roleName, bucket));

        listBucket(bucket, sessionKey).statusCode(200);
    }

    @Test
    void crossAccountBucketReadIsRefusedWithoutTheRolesOwnPolicy() {
        String suffix = suffix();
        String bucket = "cross-account-noid-" + suffix;
        String roleName = "CrossNoIdentity" + suffix;
        createBucket(bucket);
        putObject(bucket, "file.txt");
        createRole(roleName);
        putBucketPolicy(bucket, """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::%s:role/%s"},
               "Action":"s3:ListBucket","Resource":"arn:aws:s3:::%s"}]}"""
                .formatted(CALLER_ACCOUNT, roleName, bucket));
        String sessionKey = assumeRole(roleName);

        listBucket(bucket, sessionKey).statusCode(403)
                .body(containsString("<Code>AccessDenied</Code>"));
    }

    @Test
    void explicitDenyInABucketPolicyRefusesTheAccountsOwnAdministrator() {
        String suffix = suffix();
        String bucket = "deny-own-admin-" + suffix;
        createBucket(bucket);
        putObject(bucket, "file.txt");
        getObject(bucket, "file.txt", OWNER_ACCOUNT).statusCode(200);

        putBucketPolicy(bucket, """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Deny","Principal":"*","Action":"s3:GetObject",
               "Resource":"arn:aws:s3:::%s/*"}]}""".formatted(bucket));

        getObject(bucket, "file.txt", OWNER_ACCOUNT).statusCode(403)
                .body(containsString("<Code>AccessDenied</Code>"));
    }

    @Test
    void aBucketPolicyConditionIsHonouredForASignedCaller() {
        String suffix = suffix();
        String bucket = "conditional-" + suffix;
        String roleName = "ConditionalReader" + suffix;
        createBucket(bucket);
        putObject(bucket, "file.txt");
        createRole(roleName);
        putRolePolicy(roleName, "s3:ListBucket", "arn:aws:s3:::" + bucket);
        String sessionKey = assumeRole(roleName);

        // The condition names a principal ARN that is not the caller's: the statement does not apply.
        putBucketPolicy(bucket, """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Principal":{"AWS":"%s"},"Action":"s3:ListBucket",
               "Resource":"arn:aws:s3:::%s",
               "Condition":{"ArnEquals":{"aws:PrincipalArn":
                 "arn:aws:sts::%s:assumed-role/SomeoneElse/floci-session"}}}]}"""
                .formatted(CALLER_ACCOUNT, bucket, CALLER_ACCOUNT));
        listBucket(bucket, sessionKey).statusCode(403)
                .body(containsString("<Code>AccessDenied</Code>"));

        // The same statement with the caller's own principal ARN in the condition.
        putBucketPolicy(bucket, """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Principal":{"AWS":"%s"},"Action":"s3:ListBucket",
               "Resource":"arn:aws:s3:::%s",
               "Condition":{"ArnEquals":{"aws:PrincipalArn":
                 "arn:aws:sts::%s:assumed-role/%s/floci-session"}}}]}"""
                .formatted(CALLER_ACCOUNT, bucket, CALLER_ACCOUNT, roleName));
        listBucket(bucket, sessionKey).statusCode(200);
    }

    // ── The secret store ───────────────────────────────────────────────────────

    @Test
    void crossAccountSecretReadNeedsTheResourcePolicyAndTheRolePolicy() {
        String suffix = suffix();
        String secretName = "cross-secret-" + suffix;
        String roleName = "SecretReader" + suffix;
        String secretArn = createSecret(secretName);
        createRole(roleName);
        putRolePolicy(roleName, "secretsmanager:GetSecretValue", secretArn);
        String sessionKey = assumeRole(roleName);

        getSecretValue(secretArn, sessionKey).statusCode(403)
                .body(containsString("AccessDenied"));

        putSecretResourcePolicy(secretArn, """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::%s:role/%s"},
               "Action":"secretsmanager:GetSecretValue","Resource":"*"}]}"""
                .formatted(CALLER_ACCOUNT, roleName));

        getSecretValue(secretArn, sessionKey).statusCode(200);
    }

    // ── Keys ───────────────────────────────────────────────────────────────────

    @Test
    void aKeyPolicyWithoutTheAccountDelegationRefusesTheAccountsOwnAdministrator() {
        String keyArn = createKey("""
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::%s:role/NobodyHere"},
               "Action":"kms:*","Resource":"*"}]}""".formatted(OWNER_ACCOUNT));

        decrypt(keyArn, "AAAA", OWNER_ACCOUNT).statusCode(403)
                .body(containsString("AccessDenied"));
    }

    @Test
    void theDefaultKeyPolicyDelegatesToTheAccountsIdentityPolicies() {
        String keyArn = createKey(null);
        // The account root's implicit full access, delegated by the default key policy: the
        // request reaches KMS, which refuses the ciphertext rather than the principal.
        decrypt(keyArn, "AAAA", OWNER_ACCOUNT).body(not(containsString("AccessDenied")));
    }

    @Test
    void crossAccountKeyUseIsRefusedUntilTheKeyPolicyNamesTheCaller() {
        String suffix = suffix();
        String roleName = "KeyUser" + suffix;
        String keyArn = createKey(null);
        createRole(roleName);
        putRolePolicy(roleName, "kms:Decrypt", "*");
        String sessionKey = assumeRole(roleName);

        decrypt(keyArn, "AAAA", sessionKey).statusCode(403)
                .body(containsString("AccessDenied"));

        putKeyPolicy(keyArn, """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::%s:root"},
               "Action":"kms:*","Resource":"*"},
              {"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::%s:role/%s"},
               "Action":"kms:Decrypt","Resource":"*"}]}"""
                .formatted(OWNER_ACCOUNT, CALLER_ACCOUNT, roleName));

        decrypt(keyArn, "AAAA", sessionKey).body(not(containsString("AccessDenied")));
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private static String suffix() {
        return UUID.randomUUID().toString().substring(0, 8);
    }

    private static void createBucket(String bucket) {
        given().header("Authorization", auth(OWNER_ACCOUNT, "s3"))
        .when().put("/" + bucket)
        .then().statusCode(200);
    }

    private static void putObject(String bucket, String key) {
        given().header("Authorization", auth(OWNER_ACCOUNT, "s3"))
                .contentType("text/plain").body("content")
        .when().put("/" + bucket + "/" + key)
        .then().statusCode(200);
    }

    private static void putBucketPolicy(String bucket, String policy) {
        given().header("Authorization", auth(OWNER_ACCOUNT, "s3"))
                .contentType("application/json").body(policy)
        .when().put("/" + bucket + "?policy")
        .then().statusCode(200);
    }

    private static io.restassured.response.ValidatableResponse getObject(
            String bucket, String key, String accessKeyId) {
        return given().header("Authorization", auth(accessKeyId, "s3"))
                .when().get("/" + bucket + "/" + key)
                .then();
    }

    /**
     * Lists the bucket. The cross-account cases read a bucket this way rather than by GetObject:
     * an object's bytes live under the account root of the account that wrote them, and floci
     * serves them from the requesting account's, so a cross-account GetObject fails in the data
     * path long after the authorization decision this test is about. Listing reads metadata only.
     */
    private static io.restassured.response.ValidatableResponse listBucket(
            String bucket, String accessKeyId) {
        return given().header("Authorization", auth(accessKeyId, "s3"))
                .queryParam("list-type", "2")
                .when().get("/" + bucket)
                .then();
    }

    private static void createRole(String roleName) {
        given().formParam("Action", "CreateRole")
                .formParam("RoleName", roleName)
                .formParam("Path", "/")
                .formParam("AssumeRolePolicyDocument", """
                    {"Version":"2012-10-17","Statement":[
                      {"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}""")
                .header("Authorization", auth(CALLER_ACCOUNT, "iam"))
        .when().post("/")
        .then().statusCode(200);
    }

    private static void putRolePolicy(String roleName, String action, String resource) {
        given().formParam("Action", "PutRolePolicy")
                .formParam("RoleName", roleName)
                .formParam("PolicyName", "Allow" + action.replace(':', '-'))
                .formParam("PolicyDocument", """
                    {"Version":"2012-10-17","Statement":[
                      {"Effect":"Allow","Action":"%s","Resource":"%s"}]}"""
                        .formatted(action, resource))
                .header("Authorization", auth(CALLER_ACCOUNT, "iam"))
        .when().post("/")
        .then().statusCode(200);
    }

    private static String assumeRole(String roleName) {
        return given().formParam("Action", "AssumeRole")
                .formParam("RoleArn", "arn:aws:iam::" + CALLER_ACCOUNT + ":role/" + roleName)
                .formParam("RoleSessionName", "resource-policy-test")
                .header("Authorization", auth(CALLER_ACCOUNT, "sts"))
        .when().post("/")
        .then().statusCode(200)
                .body("AssumeRoleResponse.AssumeRoleResult.Credentials.AccessKeyId", startsWith("ASIA"))
                .extract().path("AssumeRoleResponse.AssumeRoleResult.Credentials.AccessKeyId");
    }

    private static String createSecret(String name) {
        return given().header("Authorization", auth(OWNER_ACCOUNT, "secretsmanager"))
                .header("X-Amz-Target", "secretsmanager.CreateSecret")
                .config(JSON_1_1).contentType(JSON_CONTENT_TYPE)
                .body("{\"Name\":\"" + name + "\",\"SecretString\":\"s3cret\"}")
        .when().post("/")
        .then().statusCode(200)
                .extract().path("ARN");
    }

    private static void putSecretResourcePolicy(String secretArn, String policy) {
        given().header("Authorization", auth(OWNER_ACCOUNT, "secretsmanager"))
                .header("X-Amz-Target", "secretsmanager.PutResourcePolicy")
                .config(JSON_1_1).contentType(JSON_CONTENT_TYPE)
                .body(jsonBody(Map.of("SecretId", secretArn, "ResourcePolicy", policy)))
        .when().post("/")
        .then().statusCode(200);
    }

    private static io.restassured.response.ValidatableResponse getSecretValue(
            String secretArn, String accessKeyId) {
        return given().header("Authorization", auth(accessKeyId, "secretsmanager"))
                .header("X-Amz-Target", "secretsmanager.GetSecretValue")
                .config(JSON_1_1).contentType(JSON_CONTENT_TYPE)
                .body(jsonBody(Map.of("SecretId", secretArn)))
                .when().post("/")
                .then();
    }

    private static String createKey(String policy) {
        String body = policy == null
                ? "{\"Description\":\"resource policy test\"}"
                : jsonBody(Map.of("Description", "resource policy test", "Policy", policy));
        return given().header("Authorization", auth(OWNER_ACCOUNT, "kms"))
                .header("X-Amz-Target", "TrentService.CreateKey")
                .config(JSON_1_1).contentType(JSON_CONTENT_TYPE)
                .body(body)
        .when().post("/")
        .then().statusCode(200)
                .extract().path("KeyMetadata.Arn");
    }

    private static void putKeyPolicy(String keyArn, String policy) {
        given().header("Authorization", auth(OWNER_ACCOUNT, "kms"))
                .header("X-Amz-Target", "TrentService.PutKeyPolicy")
                .config(JSON_1_1).contentType(JSON_CONTENT_TYPE)
                .body(jsonBody(Map.of("KeyId", keyArn, "PolicyName", "default", "Policy", policy)))
        .when().post("/")
        .then().statusCode(200);
    }

    private static io.restassured.response.ValidatableResponse decrypt(
            String keyArn, String ciphertext, String accessKeyId) {
        return given().header("Authorization", auth(accessKeyId, "kms"))
                .header("X-Amz-Target", "TrentService.Decrypt")
                .config(JSON_1_1).contentType(JSON_CONTENT_TYPE)
                .body(jsonBody(Map.of("KeyId", keyArn, "CiphertextBlob", ciphertext)))
                .when().post("/")
                .then();
    }

    /** Minimal JSON object writer: the values here are plain strings, policies among them. */
    private static String jsonBody(Map<String, String> fields) {
        StringBuilder out = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, String> field : fields.entrySet()) {
            if (!first) {
                out.append(',');
            }
            first = false;
            out.append('"').append(field.getKey()).append("\":\"")
                    .append(field.getValue()
                            .replace("\\", "\\\\")
                            .replace("\"", "\\\"")
                            .replace("\n", "\\n"))
                    .append('"');
        }
        return out.append('}').toString();
    }

    private static String auth(String accessKeyId, String service) {
        return "AWS4-HMAC-SHA256 Credential=" + accessKeyId + "/20260629/" + REGION + "/" + service
                + "/aws4_request, SignedHeaders=host, Signature=abc";
    }

    public static final class ResourcePolicyProfile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of(
                    "floci.services.iam.enforcement-enabled", "true",
                    "floci.services.s3.global-bucket-namespace", "true");
        }
    }
}

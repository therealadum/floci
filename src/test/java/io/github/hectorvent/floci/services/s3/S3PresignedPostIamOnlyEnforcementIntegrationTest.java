package io.github.hectorvent.floci.services.s3;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

/**
 * Regression coverage for the presigned POST gap in #3195/#3504: {@code S3Controller} only ran
 * {@code IamEnforcementFilter#authorizeAdditionalResource} inside {@code validatePresignedPostAuth},
 * which itself only runs when {@code floci.services.s3.enforce-auth} is enabled. With that flag
 * left off (its default) and only {@code floci.services.iam.enforcement-enabled} turned on, a
 * presigned POST never reached the signing principal's identity policy at all, so an explicit
 * {@code Deny} had no effect even though the equivalent header-signed and presigned-URL requests
 * were already correctly denied. This mirrors {@code S3PresignedUrlIamEnforcementIntegrationTest}'s
 * IAM-only profile, which the combined-flags profile in
 * {@code S3PresignedPostAuthEnforcementIntegrationTest} cannot exercise.
 */
@QuarkusTest
@TestProfile(S3PresignedPostIamOnlyEnforcementIntegrationTest.IamOnlyProfile.class)
class S3PresignedPostIamOnlyEnforcementIntegrationTest {

    private static final String REGION = "us-east-1";
    /** Under enforcement the emulator's one default credential is the seeded deployer. */
    private static final String DEPLOYER_ACCESS_KEY_ID = "floci";
    /** A non-default account, distinct from the configured {@code 000000000000} default. */
    private static final String NON_DEFAULT_ACCOUNT = "222233334444";
    private static final DateTimeFormatter AMZ_DATE_FMT =
            DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").withZone(ZoneOffset.UTC);

    @Test
    void presignedPostIsDeniedWhenIdentityPolicyDeniesPutObject() {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String bucket = "presigned-post-iam-deny-" + suffix;
        String userName = "presigned-post-denied-user-" + suffix;

        createBucketAsRoot(bucket);
        String accessKeyId = createUser(userName);
        putUserPolicy(userName, "DenyPutObject", """
                {"Version":"2012-10-17","Statement":[
                  {"Effect":"Deny","Action":"s3:PutObject","Resource":"*"}
                ]}""");

        given()
                .multiPart("key", "denied.txt")
                .multiPart("x-amz-credential", presignedCredential(accessKeyId))
                .multiPart("file", "denied.txt",
                        "should not be stored".getBytes(StandardCharsets.UTF_8), "text/plain")
        .when()
                .post("/" + bucket)
        .then()
                .statusCode(403)
                .body("Error.Code", equalTo("AccessDenied"));
    }

    @Test
    void presignedPostSucceedsWhenIdentityPolicyAllowsPutObject() {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String bucket = "presigned-post-iam-allow-" + suffix;
        String userName = "presigned-post-allowed-user-" + suffix;

        createBucketAsRoot(bucket);
        String accessKeyId = createUser(userName);
        putUserPolicy(userName, "AllowPutObject", """
                {"Version":"2012-10-17","Statement":[
                  {"Effect":"Allow","Action":"s3:PutObject","Resource":"arn:aws:s3:::%1$s/*"}
                ]}""".formatted(bucket));

        given()
                .multiPart("key", "allowed.txt")
                .multiPart("x-amz-credential", presignedCredential(accessKeyId))
                .multiPart("file", "allowed.txt",
                        "uploaded via presigned POST".getBytes(StandardCharsets.UTF_8), "text/plain")
        .when()
                .post("/" + bucket)
        .then()
                .statusCode(204);
    }

    /**
     * Regression for the multi-account gap found in review on #3504: {@code AccountContextFilter}
     * runs before the multipart body is parsed, so for a presigned POST it sets the ambient
     * request account to the configured default. An IAM user (and access key) created in a
     * non-default account must still be resolved from the parsed credential rather than looked
     * up in that ambient default account, or its identity policy is silently skipped via the
     * unknown-key bypass instead of being evaluated.
     */
    @Test
    void presignedPostIsDeniedForNonDefaultAccountKeyWhenIdentityPolicyDenies() {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String bucket = "presigned-post-iam-deny-xacct-" + suffix;
        String userName = "presigned-post-denied-xacct-user-" + suffix;

        createBucketAsRoot(bucket);
        // The bucket belongs to the default account and the user to another, so a bucket policy
        // admitting that account is what makes the request cross-account-legal at all. Without it
        // the cross-account rule refuses before any identity policy is read, and the
        // identity-policy evaluation this test is about would never show.
        allowAccountInBucketPolicy(bucket, NON_DEFAULT_ACCOUNT);
        String accessKeyId = createUser(userName, NON_DEFAULT_ACCOUNT);
        putUserPolicy(userName, "DenyPutObject", """
                {"Version":"2012-10-17","Statement":[
                  {"Effect":"Deny","Action":"s3:PutObject","Resource":"*"}
                ]}""", NON_DEFAULT_ACCOUNT);

        given()
                .multiPart("key", "denied-xacct.txt")
                .multiPart("x-amz-credential", presignedCredential(accessKeyId))
                .multiPart("file", "denied-xacct.txt",
                        "should not be stored".getBytes(StandardCharsets.UTF_8), "text/plain")
        .when()
                .post("/" + bucket)
        .then()
                .statusCode(403)
                .body("Error.Code", equalTo("AccessDenied"));
    }

    /** Allow counterpart of {@link #presignedPostIsDeniedForNonDefaultAccountKeyWhenIdentityPolicyDenies}. */
    @Test
    void presignedPostSucceedsForNonDefaultAccountKeyWhenIdentityPolicyAllows() {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String bucket = "presigned-post-iam-allow-xacct-" + suffix;
        String userName = "presigned-post-allowed-xacct-user-" + suffix;

        createBucketAsRoot(bucket);
        allowAccountInBucketPolicy(bucket, NON_DEFAULT_ACCOUNT);
        String accessKeyId = createUser(userName, NON_DEFAULT_ACCOUNT);
        putUserPolicy(userName, "AllowPutObject", """
                {"Version":"2012-10-17","Statement":[
                  {"Effect":"Allow","Action":"s3:PutObject","Resource":"arn:aws:s3:::%1$s/*"}
                ]}""".formatted(bucket), NON_DEFAULT_ACCOUNT);

        given()
                .multiPart("key", "allowed-xacct.txt")
                .multiPart("x-amz-credential", presignedCredential(accessKeyId))
                .multiPart("file", "allowed-xacct.txt",
                        "uploaded via presigned POST".getBytes(StandardCharsets.UTF_8), "text/plain")
        .when()
                .post("/" + bucket)
        .then()
                .statusCode(204);
    }

    private static String presignedCredential(String accessKeyId) {
        String amzDate = AMZ_DATE_FMT.format(Instant.now());
        String dateStamp = amzDate.substring(0, 8);
        return accessKeyId + "/" + dateStamp + "/" + REGION + "/s3/aws4_request";
    }

    /** Admits every principal of {@code accountId} to write objects, as AWS's cross-account rule needs. */
    private static void allowAccountInBucketPolicy(String bucket, String accountId) {
        given()
                .header("Authorization", auth(DEPLOYER_ACCESS_KEY_ID, "s3"))
                .contentType("application/json")
                .body("""
                    {"Version":"2012-10-17","Statement":[
                      {"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::%s:root"},
                       "Action":"s3:PutObject","Resource":"arn:aws:s3:::%s/*"}]}"""
                        .formatted(accountId, bucket))
        .when()
                .put("/" + bucket + "?policy")
        .then()
                .statusCode(200);
    }

    private static void createBucketAsRoot(String bucket) {
        given()
                .header("Authorization", auth(DEPLOYER_ACCESS_KEY_ID, "s3"))
        .when()
                .put("/" + bucket)
        .then()
                .statusCode(200);
    }

    private static String createUser(String userName) {
        return createUser(userName, null);
    }

    /** Creates the user (and its access key) as root in {@code accountId}, or the default account when null. */
    private static String createUser(String userName, String accountId) {
        String authHeader = auth(accountId == null ? DEPLOYER_ACCESS_KEY_ID : accountId, "iam");
        given()
                .formParam("Action", "CreateUser")
                .formParam("UserName", userName)
                .header("Authorization", authHeader)
        .when()
                .post("/")
        .then()
                .statusCode(200);

        return given()
                .formParam("Action", "CreateAccessKey")
                .formParam("UserName", userName)
                .header("Authorization", authHeader)
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .extract()
                .path("CreateAccessKeyResponse.CreateAccessKeyResult.AccessKey.AccessKeyId");
    }

    private static void putUserPolicy(String userName, String policyName, String policyDocument) {
        putUserPolicy(userName, policyName, policyDocument, null);
    }

    /** Attaches the policy as root in {@code accountId}, or the default account when null. */
    private static void putUserPolicy(String userName, String policyName, String policyDocument, String accountId) {
        given()
                .formParam("Action", "PutUserPolicy")
                .formParam("UserName", userName)
                .formParam("PolicyName", policyName)
                .formParam("PolicyDocument", policyDocument)
                .header("Authorization", auth(accountId == null ? DEPLOYER_ACCESS_KEY_ID : accountId, "iam"))
        .when()
                .post("/")
        .then()
                .statusCode(200);
    }

    private static String auth(String accessKeyId, String service) {
        String amzDate = AMZ_DATE_FMT.format(Instant.now()).substring(0, 8);
        return "AWS4-HMAC-SHA256 Credential=" + accessKeyId + "/" + amzDate + "/" + REGION + "/" + service
                + "/aws4_request, SignedHeaders=host, Signature=abc";
    }

    public static final class IamOnlyProfile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of(
                    "floci.services.iam.enforcement-enabled", "true",
                    "floci.services.s3.enforce-auth", "false",
                    "floci.services.iam.seed-deployer-principal", "true");
        }
    }
}

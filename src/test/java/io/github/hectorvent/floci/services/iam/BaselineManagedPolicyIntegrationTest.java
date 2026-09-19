package io.github.hectorvent.floci.services.iam;

import io.github.hectorvent.floci.testing.RestAssuredJsonUtils;
import io.github.hectorvent.floci.testutil.AwsRequestSigner;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.restassured.RestAssured;
import io.restassured.path.xml.XmlPath;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/**
 * The three AWS managed policies the platform attaches by name: {@code AWS_ConfigRole} for the
 * configuration recorder's role, {@code SecurityAudit} for Drata's, and
 * {@code AdministratorAccess} for the deployer and the entry role.
 *
 * <p>A managed policy is AWS's own document, named and never written, so each one has to resolve
 * from the catalog, attach, list back, and then actually grant what its document grants: a
 * catalog entry with no document is omitted and its ARN answers {@code NoSuchEntity}, which would
 * fail the attach at the first deploy. Each role here carries one managed policy and nothing
 * else, so what it may do is exactly that document.</p>
 */
@QuarkusTest
@TestProfile(BaselineManagedPolicyIntegrationTest.ManagedPolicyProfile.class)
class BaselineManagedPolicyIntegrationTest {

    private static final String REGION = "us-east-1";
    private static final String DEPLOYER_KEY = "floci";
    private static final String DEPLOYER_SECRET = "floci";
    private static final String ACCOUNT = "000000000000";
    private static final String JSON_1_1 = "application/x-amz-json-1.1";

    private static final String CONFIG_ROLE = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole";
    private static final String SECURITY_AUDIT = "arn:aws:iam::aws:policy/SecurityAudit";
    private static final String ADMINISTRATOR = "arn:aws:iam::aws:policy/AdministratorAccess";

    @BeforeEach
    void configureContentTypes() {
        RestAssuredJsonUtils.configureAwsContentTypes();
    }

    @Test
    void eachPolicyResolvesAttachesAndListsBack() {
        for (String policyArn : new String[] {CONFIG_ROLE, SECURITY_AUDIT, ADMINISTRATOR}) {
            iam(Map.of("Action", "GetPolicy", "PolicyArn", policyArn))
                    .then().statusCode(200).body(containsString("<Arn>" + policyArn + "</Arn>"));

            String roleName = createRole("attaches");
            iam(Map.of("Action", "AttachRolePolicy", "RoleName", roleName, "PolicyArn", policyArn))
                    .then().statusCode(200);
            iam(Map.of("Action", "ListAttachedRolePolicies", "RoleName", roleName))
                    .then().statusCode(200).body(containsString(policyArn));
        }
    }

    @Test
    void administratorAccessGrantsWhatItsDocumentGrants() {
        Caller admin = assume(ADMINISTRATOR);
        sns(admin, Map.of("Action", "ListTopics")).then().statusCode(200);
        sns(admin, Map.of("Action", "CreateTopic", "Name", "admin-may-create"))
                .then().statusCode(200);
    }

    @Test
    void securityAuditReadsAndNeverWrites() {
        Caller auditor = assume(SECURITY_AUDIT);
        // sns:ListTopics is in the document; sns:CreateTopic is not.
        sns(auditor, Map.of("Action", "ListTopics")).then().statusCode(200);
        sns(auditor, Map.of("Action", "CreateTopic", "Name", "auditor-may-not-create"))
                .then().statusCode(403).body(containsString("AccessDenied"));
        // Nor may it write the recorder, which is what tells it from AWS_ConfigRole below.
        config(auditor, "PutConfigurationRecorder", recorderBody("audit-recorder"))
                .then().statusCode(403);
    }

    @Test
    void awsConfigRoleWritesTheRecorderAndNothingOutsideItsDocument() {
        Caller recorder = assume(CONFIG_ROLE);
        // config:Put* is in the document, so the recorder's own write is allowed through.
        Response put = config(recorder, "PutConfigurationRecorder", recorderBody("floci-recorder"));
        assertNotEquals(403, put.statusCode(),
                "AWS_ConfigRole carries config:Put*, so the write is not an authorization refusal: "
                        + put.asString());
        sns(recorder, Map.of("Action", "ListTopics")).then().statusCode(200);
        sns(recorder, Map.of("Action", "CreateTopic", "Name", "recorder-may-not-create"))
                .then().statusCode(403).body(containsString("AccessDenied"));
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    /** One caller: an access key, its secret, and a session token where it has one. */
    private record Caller(String accessKeyId, String secretKey, String sessionToken) {
    }

    private static String recorderBody(String name) {
        return """
               {"ConfigurationRecorder":{"name":"%s",\
               "roleARN":"arn:aws:iam::%s:role/floci-config-recorder",\
               "recordingGroup":{"allSupported":true,"includeGlobalResourceTypes":true}}}"""
                .formatted(name, ACCOUNT);
    }

    /** A role carrying one managed policy and nothing else, assumed for a credential of it. */
    private static Caller assume(String policyArn) {
        String roleName = createRole("probe");
        iam(Map.of("Action", "AttachRolePolicy", "RoleName", roleName, "PolicyArn", policyArn))
                .then().statusCode(200);

        Response assumed = query("sts", DEPLOYER_KEY, DEPLOYER_SECRET, null, Map.of(
                "Action", "AssumeRole",
                "Version", "2011-06-15",
                "RoleArn", "arn:aws:iam::" + ACCOUNT + ":role/" + roleName,
                "RoleSessionName", "managed-policy"));
        assumed.then().statusCode(200);
        XmlPath credentials = XmlPath.from(assumed.asString())
                .setRoot("AssumeRoleResponse.AssumeRoleResult.Credentials");
        return new Caller(credentials.getString("AccessKeyId"),
                credentials.getString("SecretAccessKey"),
                credentials.getString("SessionToken"));
    }

    private static String createRole(String purpose) {
        String roleName = purpose + "-" + UUID.randomUUID().toString().substring(0, 8);
        iam(Map.of("Action", "CreateRole", "RoleName", roleName, "Path", "/",
                "AssumeRolePolicyDocument",
                "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\","
                        + "\"Principal\":{\"AWS\":\"arn:aws:iam::" + ACCOUNT + ":root\"},"
                        + "\"Action\":\"sts:AssumeRole\"}]}"))
                .then().statusCode(200);
        return roleName;
    }

    private static Response iam(Map<String, String> parameters) {
        Map<String, String> all = new LinkedHashMap<>(parameters);
        all.put("Version", "2010-05-08");
        return query("iam", DEPLOYER_KEY, DEPLOYER_SECRET, null, all);
    }

    private static Response sns(Caller caller, Map<String, String> parameters) {
        return query("sns", caller.accessKeyId(), caller.secretKey(), caller.sessionToken(),
                parameters);
    }

    private static Response config(Caller caller, String action, String body) {
        RequestSpecification request = given()
                .headers(sign("config", caller.accessKeyId(), caller.secretKey(), body))
                .header("X-Amz-Target", "StarlingDoveService." + action)
                .contentType(JSON_1_1)
                .body(body);
        if (caller.sessionToken() != null) {
            request = request.header("X-Amz-Security-Token", caller.sessionToken());
        }
        return request.when().post("/");
    }

    private static Response query(String service, String accessKeyId, String secretKey,
                                  String sessionToken, Map<String, String> parameters) {
        String body = AwsRequestSigner.formBody(new LinkedHashMap<>(parameters));
        RequestSpecification request = given()
                .headers(sign(service, accessKeyId, secretKey, body))
                .contentType("application/x-www-form-urlencoded")
                .body(body);
        if (sessionToken != null) {
            request = request.header("X-Amz-Security-Token", sessionToken);
        }
        return request.when().post("/");
    }

    private static Map<String, String> sign(String service, String accessKeyId, String secretKey,
                                            String body) {
        try {
            return AwsRequestSigner.signedHeaders("POST", "/", Map.of(),
                    "localhost:" + RestAssured.port, body.getBytes(StandardCharsets.UTF_8),
                    accessKeyId, secretKey, REGION, service, Instant.now());
        } catch (Exception e) {
            throw new IllegalStateException("signing failed", e);
        }
    }

    public static final class ManagedPolicyProfile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of(
                    "floci.auth.validate-signatures", "true",
                    "floci.services.iam.enforcement-enabled", "true",
                    "floci.services.iam.seed-deployer-principal", "true");
        }
    }
}

package io.github.hectorvent.floci.services.ec2;

import io.github.hectorvent.floci.testing.RestAssuredJsonUtils;
import io.github.hectorvent.floci.testutil.AwsRequestSigner;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.restassured.RestAssured;
import io.restassured.path.xml.XmlPath;
import io.restassured.response.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

/**
 * EBS encryption by default is one account's setting in one region, never one region's setting.
 *
 * <p>Every account in the organization declares it from its own baseline, so a member account
 * reading it must never see what the management account set, and turning it off in one account
 * must leave every other account alone. The setting is also per region, which the last case
 * keeps true.</p>
 *
 * <p>The member account is reached the way the platform reaches one: an account created through
 * Organizations with its entry role, assumed for a credential of that account, and every call
 * signed, with IAM enforcement on.</p>
 */
@QuarkusTest
@TestProfile(Ec2EbsEncryptionAccountIsolationIntegrationTest.IsolationProfile.class)
class Ec2EbsEncryptionAccountIsolationIntegrationTest {

    private static final String REGION = "us-east-1";
    private static final String OTHER_REGION = "eu-west-1";
    private static final String DEPLOYER_KEY = "floci";
    private static final String DEPLOYER_SECRET = "floci";
    private static final String MANAGEMENT = "000000000000";
    private static final String ENTRY_ROLE = "MycelliumEntry";
    private static final String JSON_1_1 = "application/x-amz-json-1.1";

    private static String memberAccount;
    private static String memberKey;
    private static String memberSecret;
    private static String memberToken;

    @BeforeEach
    void createAMemberAccountAndAssumeItsEntryRole() {
        RestAssuredJsonUtils.configureAwsContentTypes();
        // Built lazily: the port is not set at @BeforeAll.
        if (memberAccount != null) {
            return;
        }
        organizations("CreateOrganization", "{\"FeatureSet\":\"ALL\"}").then().statusCode(200);
        String name = "member-" + UUID.randomUUID().toString().substring(0, 8);
        memberAccount = organizations("CreateAccount", """
                {"AccountName":"%s","Email":"%s@floci.test","RoleName":"%s"}"""
                .formatted(name, name, ENTRY_ROLE))
                .then().statusCode(200).extract().path("CreateAccountStatus.AccountId");

        Response assumed = query("sts", REGION, DEPLOYER_KEY, DEPLOYER_SECRET, null, Map.of(
                "Action", "AssumeRole",
                "Version", "2011-06-15",
                "RoleArn", "arn:aws:iam::" + memberAccount + ":role/" + ENTRY_ROLE,
                "RoleSessionName", "ebs-isolation"));
        assumed.then().statusCode(200);
        XmlPath credentials = XmlPath.from(assumed.asString())
                .setRoot("AssumeRoleResponse.AssumeRoleResult.Credentials");
        memberKey = credentials.getString("AccessKeyId");
        memberSecret = credentials.getString("SecretAccessKey");
        memberToken = credentials.getString("SessionToken");
    }

    @Test
    void oneAccountsSettingIsNeverAnothersAndNeitherIsAnotherRegions() {
        // Both accounts start off, in both regions.
        assertEncryptionByDefault(management(REGION), "false");
        assertEncryptionByDefault(member(REGION), "false");

        // The management account turns it on. The member account still reads its own answer.
        ebs(management(REGION), "EnableEbsEncryptionByDefault").then().statusCode(200)
                .body("EnableEbsEncryptionByDefaultResponse.ebsEncryptionByDefault", equalTo("true"));
        assertEncryptionByDefault(management(REGION), "true");
        assertEncryptionByDefault(member(REGION), "false");

        // And the other way round: the member turns it on, then the management account turns it
        // off, and the member is untouched.
        ebs(member(REGION), "EnableEbsEncryptionByDefault").then().statusCode(200);
        assertEncryptionByDefault(member(REGION), "true");
        ebs(management(REGION), "DisableEbsEncryptionByDefault").then().statusCode(200)
                .body("DisableEbsEncryptionByDefaultResponse.ebsEncryptionByDefault", equalTo("false"));
        assertEncryptionByDefault(management(REGION), "false");
        assertEncryptionByDefault(member(REGION), "true");

        // The region is still part of the key: the member's other region is its own setting.
        assertEncryptionByDefault(member(OTHER_REGION), "false");
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    /** One caller: an access key, its secret, and a session token where it has one. */
    private record Caller(String region, String accessKeyId, String secretKey, String sessionToken) {
    }

    private static Caller management(String region) {
        return new Caller(region, DEPLOYER_KEY, DEPLOYER_SECRET, null);
    }

    private static Caller member(String region) {
        return new Caller(region, memberKey, memberSecret, memberToken);
    }

    private static void assertEncryptionByDefault(Caller caller, String expected) {
        ebs(caller, "GetEbsEncryptionByDefault").then().statusCode(200)
                .body("GetEbsEncryptionByDefaultResponse.ebsEncryptionByDefault", equalTo(expected));
    }

    private static Response ebs(Caller caller, String action) {
        return query("ec2", caller.region(), caller.accessKeyId(), caller.secretKey(),
                caller.sessionToken(), Map.of("Action", action, "Version", "2016-11-15"));
    }

    private static Response query(String service, String region, String accessKeyId,
                                  String secretKey, String sessionToken,
                                  Map<String, String> parameters) {
        String body = AwsRequestSigner.formBody(new LinkedHashMap<>(parameters));
        var request = given()
                .headers(sign(service, region, accessKeyId, secretKey, body))
                .contentType("application/x-www-form-urlencoded")
                .body(body);
        if (sessionToken != null) {
            request = request.header("X-Amz-Security-Token", sessionToken);
        }
        return request.when().post("/");
    }

    private static Response organizations(String action, String body) {
        return given()
                .headers(sign("organizations", REGION, DEPLOYER_KEY, DEPLOYER_SECRET, body))
                .header("X-Amz-Target", "AWSOrganizationsV20161128." + action)
                .contentType(JSON_1_1)
                .body(body)
                .when().post("/");
    }

    private static Map<String, String> sign(String service, String region, String accessKeyId,
                                            String secretKey, String body) {
        try {
            return AwsRequestSigner.signedHeaders("POST", "/", Map.of(),
                    "localhost:" + RestAssured.port, body.getBytes(StandardCharsets.UTF_8),
                    accessKeyId, secretKey, region, service, Instant.now());
        } catch (Exception e) {
            throw new IllegalStateException("signing failed", e);
        }
    }

    public static final class IsolationProfile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of(
                    "floci.auth.validate-signatures", "true",
                    "floci.services.iam.enforcement-enabled", "true",
                    "floci.services.iam.seed-deployer-principal", "true");
        }
    }
}

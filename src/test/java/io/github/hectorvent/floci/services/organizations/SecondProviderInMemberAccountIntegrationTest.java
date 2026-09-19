package io.github.hectorvent.floci.services.organizations;

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
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;

/**
 * One program holding two providers: the management account's own credential, and a second one
 * assuming the entry role of a member account. Both reach the same endpoint, and what each
 * declares lands in its own account and nowhere else.
 *
 * <p>This is what the Management stack does when it installs the installer, the deployer and the
 * Drata role into each member account. The emulator needs nothing beyond an {@code AssumeRole}
 * that mints a credential of the role's account and request routing that honours it; this test
 * is what proves both, with IAM enforcement on, which is how the platform runs.
 */
@QuarkusTest
@TestProfile(SecondProviderInMemberAccountIntegrationTest.SecondProviderProfile.class)
class SecondProviderInMemberAccountIntegrationTest {

    private static final String MANAGEMENT = "570000000001";
    private static final String ENTRY_ROLE = "MycelliumEntry";
    private static final String JSON_CONTENT_TYPE = "application/x-amz-json-1.1";
    private static final RestAssuredConfig JSON_1_1 = RestAssured.config()
            .encoderConfig(EncoderConfig.encoderConfig()
                    .encodeContentTypeAs(JSON_CONTENT_TYPE, ContentType.TEXT));

    private static String suffix;
    private static String memberAccount;
    private static String entrySessionKey;

    @BeforeEach
    void createTheAccountAndAssumeItsEntryRole() {
        if (suffix != null) {
            return;
        }
        suffix = UUID.randomUUID().toString().substring(0, 8);
        organizations("CreateOrganization", "{\"FeatureSet\":\"ALL\"}").then().statusCode(200);
        memberAccount = JsonPath.from(organizations("CreateAccount",
                "{\"AccountName\":\"member-" + suffix + "\",\"Email\":\"member-" + suffix
                        + "@floci.test\",\"RoleName\":\"" + ENTRY_ROLE + "\"}").asString())
                .getString("CreateAccountStatus.AccountId");

        Response assumed = given().header("Authorization", auth(MANAGEMENT, "sts"))
                .formParam("Action", "AssumeRole")
                .formParam("RoleArn", "arn:aws:iam::" + memberAccount + ":role/" + ENTRY_ROLE)
                .formParam("RoleSessionName", "second-provider")
                .when().post("/");
        assumed.then().statusCode(200)
                .body("AssumeRoleResponse.AssumeRoleResult.AssumedRoleUser.Arn",
                        containsString("arn:aws:sts::" + memberAccount + ":assumed-role/" + ENTRY_ROLE));
        entrySessionKey = XmlPath.from(assumed.asString())
                .getString("AssumeRoleResponse.AssumeRoleResult.Credentials.AccessKeyId");
    }

    @Test
    void theSecondProviderDeclaresIntoTheMemberAccountAlone() {
        createRole(entrySessionKey, "Deployer" + suffix);

        // The role is the member account's.
        getRole(memberAccount, "Deployer" + suffix).then().statusCode(200)
                .body("GetRoleResponse.GetRoleResult.Role.Arn",
                        equalTo("arn:aws:iam::" + memberAccount + ":role/Deployer" + suffix));
        // And the management account, whose program declared it, holds no copy.
        getRole(MANAGEMENT, "Deployer" + suffix).then().statusCode(404)
                .body(containsString("NoSuchEntity"));
    }

    @Test
    void theProgramsOwnCredentialStillDeclaresIntoTheManagementAccount() {
        createRole(MANAGEMENT, "Installer" + suffix);

        getRole(MANAGEMENT, "Installer" + suffix).then().statusCode(200)
                .body("GetRoleResponse.GetRoleResult.Role.Arn",
                        equalTo("arn:aws:iam::" + MANAGEMENT + ":role/Installer" + suffix));
        getRole(memberAccount, "Installer" + suffix).then().statusCode(404)
                .body(containsString("NoSuchEntity"));
    }

    @Test
    void theSessionAnswersAsTheEntryRoleOfTheMemberAccount() {
        given().header("Authorization", auth(entrySessionKey, "sts"))
                .formParam("Action", "GetCallerIdentity")
                .when().post("/")
                .then().statusCode(200)
                .body("GetCallerIdentityResponse.GetCallerIdentityResult.Arn",
                        containsString(":assumed-role/" + ENTRY_ROLE + "/"));
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private static void createRole(String accessKeyId, String roleName) {
        given().header("Authorization", auth(accessKeyId, "iam"))
                .formParam("Action", "CreateRole")
                .formParam("RoleName", roleName)
                .formParam("Path", "/")
                .formParam("AssumeRolePolicyDocument",
                        "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\","
                                + "\"Principal\":{\"Service\":\"ecs-tasks.amazonaws.com\"},"
                                + "\"Action\":\"sts:AssumeRole\"}]}")
                .when().post("/")
                .then().statusCode(200);
    }

    private static Response getRole(String accessKeyId, String roleName) {
        return given().header("Authorization", auth(accessKeyId, "iam"))
                .formParam("Action", "GetRole")
                .formParam("RoleName", roleName)
                .when().post("/");
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

    public static final class SecondProviderProfile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of("floci.services.iam.enforcement-enabled", "true");
        }
    }
}

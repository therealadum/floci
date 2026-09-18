package io.github.hectorvent.floci.services.iam;

import io.github.hectorvent.floci.testing.RestAssuredJsonUtils;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.startsWith;

/**
 * Verifies that, with {@code iam.enforcement-enabled=true}, STS AssumeRole honors the target role's
 * trust policy: a caller the trust policy permits succeeds, one it does not is denied, and a role
 * that does not exist is denied too. The entry role Organizations leaves in every account it
 * creates is exercised here for the same reason: it is a trust policy naming the management
 * account, and enforcement is what makes it mean anything.
 */
@QuarkusTest
@TestProfile(AssumeRoleTrustPolicyIntegrationTest.EnforcementProfile.class)
class AssumeRoleTrustPolicyIntegrationTest {

    public static class EnforcementProfile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of("floci.services.iam.enforcement-enabled", "true");
        }
    }

    private static final String ACCOUNT_A = "111111111111";
    private static final String ACCOUNT_B = "222222222222";
    private static final String ACCOUNT_C = "333333333333";
    private static final String MANAGEMENT_ACCOUNT = "444444444444";
    private static final String MEMBER_ACCOUNT = "555555555555";

    @BeforeAll
    static void configureRestAssured() {
        RestAssuredJsonUtils.configureAwsContentTypes();
    }

    private static final String TRUST_ALLOW_A = "{\"Version\":\"2012-10-17\",\"Statement\":[{"
            + "\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::" + ACCOUNT_A + ":root\"},"
            + "\"Action\":\"sts:AssumeRole\"}]}";

    private static String auth(String account, String service) {
        return "AWS4-HMAC-SHA256 Credential=" + account + "/20260215/us-east-1/" + service
                + "/aws4_request, SignedHeaders=host, Signature=abc";
    }

    private static void createRoleInB(String roleName) {
        given()
            .contentType("application/x-www-form-urlencoded")
            .formParam("Action", "CreateRole")
            .formParam("RoleName", roleName)
            .formParam("AssumeRolePolicyDocument", TRUST_ALLOW_A)
            .header("Authorization", auth(ACCOUNT_B, "iam"))
        .when().post("/")
        .then().statusCode(200);
    }

    @Test
    void permittedCallerCanAssumeRole() {
        String role = "trust-ok-" + UUID.randomUUID().toString().substring(0, 8);
        createRoleInB(role);

        given()
            .contentType("application/x-www-form-urlencoded")
            .formParam("Action", "AssumeRole")
            .formParam("RoleArn", "arn:aws:iam::" + ACCOUNT_B + ":role/" + role)
            .formParam("RoleSessionName", "s")
            .header("Authorization", auth(ACCOUNT_A, "sts"))
        .when().post("/")
        .then().statusCode(200)
            .body("AssumeRoleResponse.AssumeRoleResult.Credentials.AccessKeyId", startsWith("ASIA"));
    }

    @Test
    void unauthorizedCallerIsDenied() {
        String role = "trust-deny-" + UUID.randomUUID().toString().substring(0, 8);
        createRoleInB(role);

        given()
            .contentType("application/x-www-form-urlencoded")
            .formParam("Action", "AssumeRole")
            .formParam("RoleArn", "arn:aws:iam::" + ACCOUNT_B + ":role/" + role)
            .formParam("RoleSessionName", "s")
            .header("Authorization", auth(ACCOUNT_C, "sts"))
        .when().post("/")
        .then().statusCode(403)
            .body(containsString("AccessDenied"))
            // AWS prefixes the denial with the caller and names the action and resource.
            .body(containsString("User: "))
            .body(containsString("is not authorized to perform: sts:AssumeRole on resource: "
                    + "arn:aws:iam::" + ACCOUNT_B + ":role/" + role));
    }

    @Test
    void unknownRoleIsDenied() {
        // AWS denies AssumeRole on a role that does not exist, with the same AccessDenied it
        // returns for a role whose trust policy refuses the caller: it does not disclose which.
        String roleArn = "arn:aws:iam::" + ACCOUNT_B + ":role/never-created-"
                + UUID.randomUUID().toString().substring(0, 8);
        given()
            .contentType("application/x-www-form-urlencoded")
            .formParam("Action", "AssumeRole")
            .formParam("RoleArn", roleArn)
            .formParam("RoleSessionName", "s")
            .header("Authorization", auth(ACCOUNT_C, "sts"))
        .when().post("/")
        .then().statusCode(403)
            .body(containsString("AccessDenied"))
            .body(containsString("is not authorized to perform: sts:AssumeRole on resource: " + roleArn));
    }

    /**
     * The entry role CreateAccount leaves in every new account: the management account assumes it
     * with enforcement on, and the session then acts inside the new account. A principal of
     * another member account is refused by the trust policy.
     */
    @Test
    void theEntryRoleIsAssumableFromManagementAndFromNowhereElse() {
        String organizationAccount = createOrganizationAndAccount();
        String entryRoleArn = "arn:aws:iam::" + organizationAccount + ":role/OrganizationAccountAccessRole";

        String sessionKeyId = given()
            .contentType("application/x-www-form-urlencoded")
            .formParam("Action", "AssumeRole")
            .formParam("RoleArn", entryRoleArn)
            .formParam("RoleSessionName", "entry")
            .header("Authorization", auth(MANAGEMENT_ACCOUNT, "sts"))
        .when().post("/")
        .then().statusCode(200)
            .body("AssumeRoleResponse.AssumeRoleResult.Credentials.AccessKeyId", startsWith("ASIA"))
            .extract().path("AssumeRoleResponse.AssumeRoleResult.Credentials.AccessKeyId");

        // AdministratorAccess came with the role, so the session is allowed inside the new account.
        given()
            .contentType("application/x-www-form-urlencoded")
            .formParam("Action", "CreateRole")
            .formParam("RoleName", "MadeByTheEntryRole")
            .formParam("AssumeRolePolicyDocument", TRUST_ALLOW_A)
            .header("Authorization", auth(sessionKeyId, "iam"))
        .when().post("/")
        .then().statusCode(200)
            .body(containsString("arn:aws:iam::" + organizationAccount + ":role/MadeByTheEntryRole"));

        given()
            .contentType("application/x-www-form-urlencoded")
            .formParam("Action", "AssumeRole")
            .formParam("RoleArn", entryRoleArn)
            .formParam("RoleSessionName", "intruder")
            .header("Authorization", auth(MEMBER_ACCOUNT, "sts"))
        .when().post("/")
        .then().statusCode(403)
            .body(containsString("AccessDenied"))
            .body(containsString("is not authorized to perform: sts:AssumeRole on resource: " + entryRoleArn));
    }

    private static String createOrganizationAndAccount() {
        given()
            .contentType("application/x-amz-json-1.1")
            .header("X-Amz-Target", "AWSOrganizationsV20161128.CreateOrganization")
            .header("Authorization", auth(MANAGEMENT_ACCOUNT, "organizations"))
            .body("{\"FeatureSet\":\"ALL\"}")
        .when().post("/")
        .then().statusCode(200);

        return given()
            .contentType("application/x-amz-json-1.1")
            .header("X-Amz-Target", "AWSOrganizationsV20161128.CreateAccount")
            .header("Authorization", auth(MANAGEMENT_ACCOUNT, "organizations"))
            .body("{\"Email\":\"entry-role@example.com\",\"AccountName\":\"EntryRole\"}")
        .when().post("/")
        .then().statusCode(200)
            .body("CreateAccountStatus.State", equalTo("SUCCEEDED"))
            .extract().path("CreateAccountStatus.AccountId");
    }
}

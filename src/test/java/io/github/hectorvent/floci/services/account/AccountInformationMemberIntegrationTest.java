package io.github.hectorvent.floci.services.account;

import io.github.hectorvent.floci.testing.RestAssuredJsonUtils;
import io.github.hectorvent.floci.testutil.AwsRequestSigner;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.restassured.RestAssured;
import io.restassured.response.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;

/**
 * {@code GetAccountInformation} from the management account, naming a member with the
 * {@code AccountId} parameter — the shape {@code deploy management} reads an account it created.
 *
 * <p>AWS admits the parameter only to the organization's management account or a delegated
 * administrator, only for a member of the same organization, only with all features enabled and
 * trusted access for the Account Management service on, and refuses the management account naming
 * itself: it must ask in standalone context instead. Each of those is a case here.</p>
 */
@QuarkusTest
@TestProfile(AccountInformationMemberIntegrationTest.MemberAccountProfile.class)
class AccountInformationMemberIntegrationTest {

    private static final String REGION = "us-east-1";
    private static final String DEPLOYER_KEY = "floci";
    private static final String DEPLOYER_SECRET = "floci";
    /** The deployer's own account, which becomes the organization's management account. */
    private static final String MANAGEMENT = "000000000000";
    private static final String JSON_1_1 = "application/x-amz-json-1.1";
    /** An account id that is in no organization of this emulator. */
    private static final String STRANGER = "999988887777";

    private static String memberAccount;
    private static String memberName;

    @BeforeEach
    void createTheOrganizationAndAMember() {
        RestAssuredJsonUtils.configureAwsContentTypes();
        // Built lazily: the port is not set at @BeforeAll.
        if (memberAccount != null) {
            return;
        }
        organizations("CreateOrganization", "{\"FeatureSet\":\"ALL\"}").then().statusCode(200);
        organizations("EnableAWSServiceAccess",
                "{\"ServicePrincipal\":\"account.amazonaws.com\"}").then().statusCode(200);
        memberName = "member-" + UUID.randomUUID().toString().substring(0, 8);
        memberAccount = organizations("CreateAccount", """
                {"AccountName":"%s","Email":"%s@floci.test","RoleName":"MycelliumEntry"}"""
                .formatted(memberName, memberName))
                .then().statusCode(200).extract().path("CreateAccountStatus.AccountId");
    }

    @Test
    void theManagementAccountReadsAMemberByItsAccountId() {
        account("getAccountInformation", "{\"AccountId\":\"" + memberAccount + "\"}")
                .then().statusCode(200)
                .body("AccountId", equalTo(memberAccount))
                .body("AccountName", equalTo(memberName))
                .body("AccountCreatedDate", greaterThan(0.0f));
    }

    @Test
    void theManagementAccountCannotNameItself() {
        account("getAccountInformation", "{\"AccountId\":\"" + MANAGEMENT + "\"}")
                .then().statusCode(400).body("__type", equalTo("ValidationException"));
    }

    @Test
    void anAccountOutsideTheOrganizationIsRefused() {
        account("getAccountInformation", "{\"AccountId\":\"" + STRANGER + "\"}")
                .then().statusCode(403).body("__type", equalTo("AccessDeniedException"));
    }

    @Test
    void withNoAccountIdTheManagementAccountReadsItself() {
        account("getAccountInformation", "{}").then().statusCode(200)
                .body("AccountId", equalTo(MANAGEMENT))
                .body("AccountName", equalTo("management-account"));
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private static Response account(String operation, String body) {
        String path = "/" + operation;
        return given()
                .headers(sign("account", path, body))
                .contentType("application/json")
                .body(body)
                .when().post(path);
    }

    private static Response organizations(String action, String body) {
        return given()
                .headers(sign("organizations", "/", body))
                .header("X-Amz-Target", "AWSOrganizationsV20161128." + action)
                .contentType(JSON_1_1)
                .body(body)
                .when().post("/");
    }

    private static Map<String, String> sign(String service, String path, String body) {
        try {
            return AwsRequestSigner.signedHeaders("POST", path, Map.of(),
                    "localhost:" + RestAssured.port, body.getBytes(StandardCharsets.UTF_8),
                    DEPLOYER_KEY, DEPLOYER_SECRET, REGION, service, Instant.now());
        } catch (Exception e) {
            throw new IllegalStateException("signing failed", e);
        }
    }

    public static final class MemberAccountProfile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of(
                    "floci.auth.validate-signatures", "true",
                    "floci.services.iam.enforcement-enabled", "true",
                    "floci.services.iam.seed-deployer-principal", "true");
        }
    }
}

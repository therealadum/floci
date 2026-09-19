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

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * The account service as the baseline uses it, from the account the credential reaches: the
 * alternate contacts it writes, and {@code GetAccountInformation}, which is how a stack learns
 * the account id it is declaring into when the call it is about to make asks for one.
 *
 * <p>Every call is a genuinely signed request from the seeded deployer principal with IAM
 * enforcement on, which is what proves the account service is reachable at all under enforcement:
 * an action the registry cannot name is refused, and before these rules existed every account
 * call was one.</p>
 *
 * <p>This account belongs to no organization, so it is the standalone case;
 * {@link AccountInformationMemberIntegrationTest} is the management account naming a member.</p>
 */
@QuarkusTest
@TestProfile(AccountInformationIntegrationTest.StandaloneAccountProfile.class)
class AccountInformationIntegrationTest {

    private static final String REGION = "us-east-1";
    private static final String DEPLOYER_KEY = "floci";
    private static final String DEPLOYER_SECRET = "floci";
    private static final String ACCOUNT = "000000000000";

    @BeforeEach
    void configureContentTypes() {
        RestAssuredJsonUtils.configureAwsContentTypes();
    }

    @Test
    void theCredentialReachesItsOwnAccountWithItsIdNameAndCreationDate() {
        account("getAccountInformation", "{}").then().statusCode(200)
                .body("AccountId", equalTo(ACCOUNT))
                .body("AccountName", equalTo("floci"))
                .body("AccountCreatedDate", notNullValue())
                .body("AccountCreatedDate", greaterThan(0.0f));
    }

    @Test
    void theCreationDateIsTheSameOnEveryCall() {
        Object first = account("getAccountInformation", "{}")
                .then().statusCode(200).extract().path("AccountCreatedDate");
        Object second = account("getAccountInformation", "{}")
                .then().statusCode(200).extract().path("AccountCreatedDate");
        assertEquals(first, second, "an account's creation date never moves");
    }

    @Test
    void anAlternateContactIsWrittenAndReadBackUnderEnforcement() {
        account("putAlternateContact", """
                {"AlternateContactType":"SECURITY","EmailAddress":"security@mycelmedical.com",\
                "Name":"Adam Shurson","PhoneNumber":"+15550100","Title":"CTO"}""")
                .then().statusCode(200);

        account("getAlternateContact", "{\"AlternateContactType\":\"SECURITY\"}")
                .then().statusCode(200)
                .body("AlternateContact.AlternateContactType", equalTo("SECURITY"))
                .body("AlternateContact.EmailAddress", equalTo("security@mycelmedical.com"))
                .body("AlternateContact.Name", equalTo("Adam Shurson"))
                .body("AlternateContact.Title", equalTo("CTO"));
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    static Response account(String operation, String body) {
        String path = "/" + operation;
        return given()
                .headers(sign(path, body))
                .contentType("application/json")
                .body(body)
                .when().post(path);
    }

    private static Map<String, String> sign(String path, String body) {
        try {
            return AwsRequestSigner.signedHeaders("POST", path, Map.of(),
                    "localhost:" + RestAssured.port, body.getBytes(StandardCharsets.UTF_8),
                    DEPLOYER_KEY, DEPLOYER_SECRET, REGION, "account", Instant.now());
        } catch (Exception e) {
            throw new IllegalStateException("signing failed", e);
        }
    }

    public static final class StandaloneAccountProfile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of(
                    "floci.auth.validate-signatures", "true",
                    "floci.services.iam.enforcement-enabled", "true",
                    "floci.services.iam.seed-deployer-principal", "true");
        }
    }
}

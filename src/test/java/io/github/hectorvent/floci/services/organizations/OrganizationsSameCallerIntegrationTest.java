package io.github.hectorvent.floci.services.organizations;

import io.github.hectorvent.floci.testing.RestAssuredJsonUtils;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.specification.RequestSpecification;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.startsWith;

/**
 * What a provider that never retries sees from one caller: the organization a call created is
 * visible to the very next call, and closing an account reaches its terminal state at once.
 *
 * <p>Uses a management account of its own so the ordered classes in this package never contend
 * for the same organization inside one shared Quarkus instance.
 */
@QuarkusTest
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class OrganizationsSameCallerIntegrationTest {

    private static final String CONTENT_TYPE = "application/x-amz-json-1.1";
    private static final String TARGET_PREFIX = "AWSOrganizationsV20161128.";

    private static final String MANAGEMENT_ACCOUNT = "555555555555";

    private static final String SCP_CONTENT =
            "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\","
                    + "\"Action\":\"organizations:LeaveOrganization\",\"Resource\":\"*\"}]}";

    private String memberAccountId;

    @BeforeAll
    static void configureRestAssured() {
        RestAssuredJsonUtils.configureAwsContentTypes();
    }

    private RequestSpecification organizations(String action, String body) {
        return given()
                .header("Authorization", authorization())
                .header("X-Amz-Target", TARGET_PREFIX + action)
                .contentType(CONTENT_TYPE)
                .body(body);
    }

    private static String authorization() {
        return "AWS4-HMAC-SHA256 Credential=" + MANAGEMENT_ACCOUNT
                + "/20260916/us-east-1/organizations/aws4_request, SignedHeaders=host, Signature=abc";
    }

    @Test
    @Order(1)
    void anOrganizationIsVisibleToTheVeryNextCallFromTheSameCaller() {
        organizations("CreateOrganization", "{\"FeatureSet\":\"ALL\"}")
        .when()
            .post("/")
        .then()
            .statusCode(200)
            .body("Organization.MasterAccountId", equalTo(MANAGEMENT_ACCOUNT));

        organizations("CreatePolicy", "{\"Name\":\"deny-leave\",\"Type\":\"SERVICE_CONTROL_POLICY\","
                + "\"Description\":\"deny leave\",\"Content\":" + quoted(SCP_CONTENT) + "}")
        .when()
            .post("/")
        .then()
            .statusCode(200)
            .body("Policy.PolicySummary.Name", equalTo("deny-leave"))
            .body("Policy.PolicySummary.Arn",
                    startsWith("arn:aws:organizations::" + MANAGEMENT_ACCOUNT + ":policy/"));
    }

    @Test
    @Order(2)
    void createAccountForClosure() {
        memberAccountId = organizations("CreateAccount",
                "{\"Email\":\"closing@example.com\",\"AccountName\":\"Closing\"}")
        .when()
            .post("/")
        .then()
            .statusCode(200)
            .body("CreateAccountStatus.State", equalTo("SUCCEEDED"))
            .body("CreateAccountStatus.AccountId", notNullValue())
            .extract().jsonPath().getString("CreateAccountStatus.AccountId");
    }

    @Test
    @Order(3)
    void closeAccountReachesStateClosedWithStatusSuspendedAtOnce() {
        organizations("CloseAccount", "{\"AccountId\":\"" + memberAccountId + "\"}")
        .when()
            .post("/")
        .then()
            .statusCode(200);

        organizations("DescribeAccount", "{\"AccountId\":\"" + memberAccountId + "\"}")
        .when()
            .post("/")
        .then()
            .statusCode(200)
            .body("Account.State", equalTo("CLOSED"))
            .body("Account.Status", equalTo("SUSPENDED"));

        organizations("ListAccounts", "{}")
        .when()
            .post("/")
        .then()
            .statusCode(200)
            .body("Accounts.findAll { it.Id == '" + memberAccountId + "' }.State", hasItem("CLOSED"))
            .body("Accounts.findAll { it.Id == '" + memberAccountId + "' }.Status", hasItem("SUSPENDED"));
    }

    private static String quoted(String value) {
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }
}

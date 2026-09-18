package io.github.hectorvent.floci.core.common;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;

/**
 * With {@code floci.services.iam.enforcement-enabled} on, nothing is allowed by default: the four
 * credentials and requests that earlier releases let through are refused instead.
 *
 * <p>Signature validation is off here, so each case is about the principal and the action alone.
 */
@QuarkusTest
@TestProfile(IamEnforcementRefusalIntegrationTest.EnforcementProfile.class)
class IamEnforcementRefusalIntegrationTest {

    private static final String REGION = "us-east-1";

    @Test
    void theTestCredentialIsNoLongerARootBypass() {
        given()
                .header("Authorization", auth("test", "s3"))
        .when()
                .get("/")
        .then()
                .statusCode(403)
                .body(containsString("<Code>AccessDenied</Code>"));
    }

    @Test
    void anAccessKeyThisAccountNeverIssuedIsRefused() {
        given()
                .header("Authorization", auth("AKIANEVERISSUED", "s3"))
        .when()
                .get("/")
        .then()
                .statusCode(403)
                .body(containsString("<Code>AccessDenied</Code>"));
    }

    @Test
    void anActionTheRegistryCannotNameIsRefused() {
        // /domainnames is a real API Gateway route with no rule in IamActionRegistry. An action
        // nobody can name is an action no policy can allow, so enforcement refuses it rather than
        // granting, by omission, exactly the calls no rule was written for.
        given()
                .header("Authorization", auth("floci", "apigateway"))
        .when()
                .get("/domainnames")
        .then()
                .statusCode(403);
    }

    @Test
    void theSeededDeployerPrincipalIsTheOneDefaultCredential() {
        given()
                .header("Authorization", auth("floci", "s3"))
        .when()
                .get("/")
        .then()
                .statusCode(200);
    }

    @Test
    void anUnsignedRequestIsStillDecidedByItsRoute() {
        // No AWS credential at all: there is no principal to evaluate, so enforcement stays out of
        // the way and the route answers as it always did.
        given()
        .when()
                .get("/health")
        .then()
                .statusCode(200);
    }

    private static String auth(String accessKeyId, String service) {
        return "AWS4-HMAC-SHA256 Credential=" + accessKeyId + "/20260918/" + REGION + "/" + service
                + "/aws4_request, SignedHeaders=host, Signature=unverified";
    }

    public static final class EnforcementProfile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of(
                    "floci.services.iam.enforcement-enabled", "true",
                    "floci.services.iam.seed-deployer-principal", "true");
        }
    }
}

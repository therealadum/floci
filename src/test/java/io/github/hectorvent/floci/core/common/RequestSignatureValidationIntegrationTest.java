package io.github.hectorvent.floci.core.common;

import io.github.hectorvent.floci.testutil.AwsRequestSigner;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.restassured.RestAssured;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;

/**
 * {@code floci.auth.validate-signatures} on: every signed request has its SigV4 signature checked
 * before anything downstream reads the access key off it, so the key stops being a claim the
 * caller simply makes.
 *
 * <p>The signatures here are produced by {@link AwsRequestSigner}, not by the code under test.
 * IAM enforcement is deliberately left off, so what these cases prove is authentication alone.
 */
@QuarkusTest
@TestProfile(RequestSignatureValidationIntegrationTest.ValidateSignaturesProfile.class)
class RequestSignatureValidationIntegrationTest {

    private static final String REGION = "us-east-1";
    /** The seeded deployer principal: the emulator's one default credential under enforcement. */
    private static final String DEPLOYER_KEY = "floci";
    private static final String DEPLOYER_SECRET = "floci";

    private static String host() {
        return "localhost:" + RestAssured.port;
    }

    @Test
    void aGenuinelySignedQueryRequestIsAccepted() throws Exception {
        String body = AwsRequestSigner.formBody(Map.of("Action", "ListUsers", "Version", "2010-05-08"));

        given()
                .headers(signed("POST", "/", body, DEPLOYER_SECRET, Instant.now()))
                .contentType("application/x-www-form-urlencoded")
                .body(body)
        .when()
                .post("/")
        .then()
                .statusCode(200);
    }

    @Test
    void aSignatureMintedWithTheWrongSecretIsRefused() throws Exception {
        String body = AwsRequestSigner.formBody(Map.of("Action", "ListUsers", "Version", "2010-05-08"));

        given()
                .headers(signed("POST", "/", body, "not-the-deployer-secret", Instant.now()))
                .contentType("application/x-www-form-urlencoded")
                .body(body)
        .when()
                .post("/")
        .then()
                .statusCode(403)
                .body(containsString("<Code>SignatureDoesNotMatch</Code>"));
    }

    @Test
    void anAccessKeyThisEmulatorNeverIssuedIsRefused() throws Exception {
        // Including the well-known "test" credential: it has no registered secret, so it cannot
        // produce a signature, and a credential nobody has to prove is exactly what this closes.
        String body = AwsRequestSigner.formBody(Map.of("Action", "ListUsers", "Version", "2010-05-08"));
        Map<String, String> headers = AwsRequestSigner.signedHeaders(
                "POST", "/", Map.of(), host(), body.getBytes(StandardCharsets.UTF_8),
                "test", "test", REGION, "iam", Instant.now());

        given()
                .headers(headers)
                .contentType("application/x-www-form-urlencoded")
                .body(body)
        .when()
                .post("/")
        .then()
                .statusCode(403)
                .body(containsString("<Code>InvalidClientTokenId</Code>"));
    }

    @Test
    void anAuthorizationHeaderCarryingNoSignatureIsRefusedAsIncomplete() {
        given()
                .header("Authorization", "AWS4-HMAC-SHA256 Credential=" + DEPLOYER_KEY
                        + "/20260918/" + REGION + "/iam/aws4_request, SignedHeaders=host;x-amz-date")
                .header("X-Amz-Date", "20260918T000000Z")
                .contentType("application/x-www-form-urlencoded")
                .body("Action=ListUsers&Version=2010-05-08")
        .when()
                .post("/")
        .then()
                .statusCode(400)
                .body(containsString("<Code>IncompleteSignature</Code>"));
    }

    @Test
    void aSignatureOutsideTheAcceptedWindowIsRefused() throws Exception {
        String body = AwsRequestSigner.formBody(Map.of("Action", "ListUsers", "Version", "2010-05-08"));

        given()
                .headers(signed("POST", "/", body, DEPLOYER_SECRET, Instant.now().minus(2, ChronoUnit.HOURS)))
                .contentType("application/x-www-form-urlencoded")
                .body(body)
        .when()
                .post("/")
        .then()
                .statusCode(403)
                .body(containsString("<Code>SignatureDoesNotMatch</Code>"));
    }

    @Test
    void aBodyReplacedAfterSigningIsRefused() throws Exception {
        String honest = AwsRequestSigner.formBody(Map.of("Action", "ListUsers", "Version", "2010-05-08"));

        given()
                .headers(signed("POST", "/", honest, DEPLOYER_SECRET, Instant.now()))
                .contentType("application/x-www-form-urlencoded")
                .body(AwsRequestSigner.formBody(Map.of("Action", "ListRoles", "Version", "2010-05-08")))
        .when()
                .post("/")
        .then()
                .statusCode(403)
                .body(containsString("<Code>SignatureDoesNotMatch</Code>"));
    }

    @Test
    void aSignedS3RequestIsAcceptedAndItsBodyStillReachesTheService() throws Exception {
        // The body is buffered to hash it, then handed back: a PUT whose bytes are read twice has
        // to arrive intact, or signature validation would be a data-loss bug.
        String bucket = "signed-" + UUID.randomUUID().toString().substring(0, 8);
        byte[] payload = "the object body".getBytes(StandardCharsets.UTF_8);

        given()
                .headers(AwsRequestSigner.signedHeaders("PUT", "/" + bucket, Map.of(), host(),
                        new byte[0], DEPLOYER_KEY, DEPLOYER_SECRET, REGION, "s3", Instant.now()))
        .when()
                .put("/" + bucket)
        .then()
                .statusCode(200);

        given()
                .headers(AwsRequestSigner.signedHeaders("PUT", "/" + bucket + "/object.txt", Map.of(),
                        host(), payload, DEPLOYER_KEY, DEPLOYER_SECRET, REGION, "s3", Instant.now()))
                .contentType("text/plain")
                .body(payload)
        .when()
                .put("/" + bucket + "/object.txt")
        .then()
                .statusCode(200);

        given()
                .headers(AwsRequestSigner.signedHeaders("GET", "/" + bucket + "/object.txt", Map.of(),
                        host(), new byte[0], DEPLOYER_KEY, DEPLOYER_SECRET, REGION, "s3", Instant.now()))
        .when()
                .get("/" + bucket + "/object.txt")
        .then()
                .statusCode(200)
                .body(containsString("the object body"));
    }

    @Test
    void anUnsignedRequestToAnInternalRouteIsUntouched() {
        given()
        .when()
                .get("/health")
        .then()
                .statusCode(200);
    }

    private static Map<String, String> signed(String method, String path, String body,
                                              String secret, Instant signedAt) throws Exception {
        return AwsRequestSigner.signedHeaders(method, path, Map.of(), host(),
                body.getBytes(StandardCharsets.UTF_8), DEPLOYER_KEY, secret, REGION, "iam", signedAt);
    }

    public static final class ValidateSignaturesProfile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of(
                    "floci.auth.validate-signatures", "true",
                    "floci.services.iam.seed-deployer-principal", "true");
        }
    }
}

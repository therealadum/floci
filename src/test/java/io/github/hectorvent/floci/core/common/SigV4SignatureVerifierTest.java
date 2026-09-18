package io.github.hectorvent.floci.core.common;

import io.github.hectorvent.floci.testutil.AwsRequestSigner;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The one canonical-request implementation, exercised against signatures produced independently by
 * {@link AwsRequestSigner} rather than against fixtures the verifier made itself.
 */
class SigV4SignatureVerifierTest {

    private static final String HOST = "localhost:4566";
    private static final String REGION = "us-east-1";
    private static final String KEY = "AKIAEXAMPLE";
    private static final String SECRET = "secret-example";

    private static final SigV4SignatureVerifier.SecretLookup KNOWN_KEY =
            (accessKeyId, sessionToken) -> KEY.equals(accessKeyId) ? SECRET : null;

    @Test
    void aGenuineSignatureVerifies() throws Exception {
        FakeRequest request = signed("GET", "/", Map.of("Action", "ListUsers"), new byte[0], SECRET, Instant.now());

        assertTrue(verify(request).verified(), String.valueOf(verify(request).detail()));
    }

    @Test
    void aSignatureMintedWithAnotherSecretDoesNotVerify() throws Exception {
        FakeRequest request = signed("GET", "/", Map.of(), new byte[0], "another-secret", Instant.now());

        assertEquals(SigV4SignatureVerifier.Failure.MISMATCH, verify(request).failure());
    }

    @Test
    void anAccessKeyCannotSignForItself() throws Exception {
        // The self-signing bypass: an unregistered key used as its own secret must not verify.
        FakeRequest request = signed("GET", "/", Map.of(), new byte[0], SECRET, Instant.now());
        request.headers.put("Authorization",
                request.headers.get("Authorization").replace(KEY + "/", "AKIAUNKNOWN/"));

        assertEquals(SigV4SignatureVerifier.Failure.UNKNOWN_KEY, verify(request).failure());
    }

    @Test
    void aSwappedBodyIsASignatureMismatch() throws Exception {
        // The body is hashed rather than x-amz-content-sha256 being taken on trust, so a body
        // replaced after signing cannot keep the signature that covered the original.
        FakeRequest request = signed("POST", "/", Map.of(),
                "Action=CreateUser&UserName=honest".getBytes(StandardCharsets.UTF_8), SECRET, Instant.now());
        request.body = "Action=CreateUser&UserName=forged".getBytes(StandardCharsets.UTF_8);

        assertEquals(SigV4SignatureVerifier.Failure.MISMATCH, verify(request).failure());
    }

    @Test
    void aQueryParameterAddedAfterSigningIsASignatureMismatch() throws Exception {
        FakeRequest request = signed("GET", "/", Map.of("Action", "ListUsers"), new byte[0], SECRET, Instant.now());
        request.rawQuery = "Action=ListUsers&MaxItems=1000";

        assertEquals(SigV4SignatureVerifier.Failure.MISMATCH, verify(request).failure());
    }

    @Test
    void aStaleSignatureIsRejectedOnItsDateRatherThanItsSignature() throws Exception {
        FakeRequest request = signed("GET", "/", Map.of(), new byte[0], SECRET,
                Instant.now().minus(2, ChronoUnit.HOURS));

        assertEquals(SigV4SignatureVerifier.Failure.EXPIRED_SIGNATURE, verify(request).failure());
    }

    @Test
    void aCredentialScopeDateThatDisagreesWithAmzDateIsMalformed() throws Exception {
        FakeRequest request = signed("GET", "/", Map.of(), new byte[0], SECRET, Instant.now());
        request.headers.put("Authorization",
                request.headers.get("Authorization").replaceFirst("/\\d{8}/", "/20200101/"));

        assertEquals(SigV4SignatureVerifier.Failure.MALFORMED, verify(request).failure());
    }

    @Test
    void anAuthorizationHeaderWithNoSignatureIsIncomplete() throws Exception {
        FakeRequest request = signed("GET", "/", Map.of(), new byte[0], SECRET, Instant.now());
        request.headers.put("Authorization",
                request.headers.get("Authorization").replaceFirst(", Signature=[0-9a-f]+", ""));

        assertEquals(SigV4SignatureVerifier.Failure.INCOMPLETE, verify(request).failure());
    }

    @Test
    void anUnsignedRequestCarriesNothingToVerify() {
        FakeRequest request = new FakeRequest("GET", "/", null, HOST);

        assertNull(SigV4SignatureVerifier.read(request));
    }

    @Test
    void aBearerTokenIsNotAnAwsSignature() {
        FakeRequest request = new FakeRequest("GET", "/", null, HOST);
        request.headers.put("Authorization", "Bearer an-application-token");

        assertNull(SigV4SignatureVerifier.read(request));
    }

    @Test
    void anUnsignedPayloadSentinelIsHonouredWhenTheSignatureCoversIt() throws Exception {
        // S3 signs large and streaming bodies this way: the sentinel stands in for the body hash,
        // so the body itself is never read and a request that sends one still verifies.
        Instant now = Instant.now();
        FakeRequest request = new FakeRequest("PUT", "/bucket/key", null, HOST);
        request.headers.put("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        request.body = "payload the signature does not cover".getBytes(StandardCharsets.UTF_8);
        request.signWith("PUT", "/bucket/key", "s3", "UNSIGNED-PAYLOAD", now);

        assertTrue(verify(request).verified(), String.valueOf(verify(request).detail()));
    }

    private static SigV4SignatureVerifier.Result verify(FakeRequest request) {
        return SigV4SignatureVerifier.verify(
                request, SigV4SignatureVerifier.read(request), KNOWN_KEY, null, null, false);
    }

    private static FakeRequest signed(String method, String path, Map<String, String> query,
                                      byte[] body, String secret, Instant signedAt) throws Exception {
        StringBuilder rawQuery = new StringBuilder();
        for (Map.Entry<String, String> entry : new java.util.TreeMap<>(query).entrySet()) {
            if (!rawQuery.isEmpty()) {
                rawQuery.append('&');
            }
            rawQuery.append(entry.getKey()).append('=').append(entry.getValue());
        }
        FakeRequest request = new FakeRequest(method, path,
                rawQuery.isEmpty() ? null : rawQuery.toString(), HOST);
        request.body = body;
        request.headers.putAll(AwsRequestSigner.signedHeaders(
                method, path, query, HOST, body, KEY, secret, REGION, "iam", signedAt));
        return request;
    }

    /** A request as the verifier reads one, with every part a test may need to tamper with. */
    private static final class FakeRequest implements SigV4SignatureVerifier.Request {

        private final String method;
        private final String rawPath;
        private final String host;
        private final Map<String, String> headers = new HashMap<>();
        private String rawQuery;
        private byte[] body = new byte[0];

        private FakeRequest(String method, String rawPath, String rawQuery, String host) {
            this.method = method;
            this.rawPath = rawPath;
            this.rawQuery = rawQuery;
            this.host = host;
        }

        private void signWith(String method, String path, String service, String payloadHash, Instant signedAt)
                throws Exception {
            // Signs host;x-amz-content-sha256;x-amz-date so the payload sentinel is itself covered,
            // which is the only shape in which the verifier honours it.
            String amzDate = java.time.format.DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'")
                    .withZone(java.time.ZoneOffset.UTC).format(signedAt);
            String scopeDate = amzDate.substring(0, 8);
            String scope = scopeDate + "/" + REGION + "/" + service + "/aws4_request";
            String canonicalRequest = method + "\n" + path + "\n" + "\n"
                    + "host:" + host + "\n"
                    + "x-amz-content-sha256:" + payloadHash + "\n"
                    + "x-amz-date:" + amzDate + "\n\n"
                    + "host;x-amz-content-sha256;x-amz-date\n"
                    + payloadHash;
            String stringToSign = "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n"
                    + SigV4SignatureVerifier.sha256Hex(canonicalRequest.getBytes(StandardCharsets.UTF_8));
            byte[] signingKey = SigV4SignatureVerifier.deriveSigningKey(SECRET, scopeDate, REGION, service);
            headers.put("X-Amz-Date", amzDate);
            headers.put("Authorization", "AWS4-HMAC-SHA256 Credential=" + KEY + "/" + scope
                    + ", SignedHeaders=host;x-amz-content-sha256;x-amz-date"
                    + ", Signature=" + SigV4SignatureVerifier.hexEncode(
                            SigV4SignatureVerifier.hmacSha256(signingKey, stringToSign)));
        }

        @Override
        public String method() {
            return method;
        }

        @Override
        public String rawPath() {
            return rawPath;
        }

        @Override
        public String rawQuery() {
            return rawQuery;
        }

        @Override
        public String host() {
            return host;
        }

        @Override
        public String header(String name) {
            for (Map.Entry<String, String> entry : headers.entrySet()) {
                if (entry.getKey().equalsIgnoreCase(name)) {
                    return entry.getValue();
                }
            }
            return null;
        }

        @Override
        public String queryParameter(String name) {
            if (rawQuery == null) {
                return null;
            }
            for (String pair : rawQuery.split("&")) {
                int equals = pair.indexOf('=');
                if (equals > 0 && pair.substring(0, equals).equals(name)) {
                    return pair.substring(equals + 1);
                }
            }
            return null;
        }

        @Override
        public byte[] body() {
            return body;
        }
    }
}

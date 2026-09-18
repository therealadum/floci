package io.github.hectorvent.floci.testutil;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;

/**
 * Signs a request to any AWS service the way an SDK signer would, so tests can exercise
 * {@code SignatureValidationFilter} against real signatures rather than against fixtures produced
 * by the same code under test.
 *
 * <p>{@code ExecuteApiRequestSigner} is the same idea pinned to {@code execute-api} and to the
 * canonical form the API Gateway data plane sees; this one takes the service as a parameter and
 * signs {@code host} and {@code x-amz-date} only, which is all a control-plane call needs.
 */
public final class AwsRequestSigner {

    private static final DateTimeFormatter AMZ_DATE =
            DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").withZone(ZoneOffset.UTC);
    private static final DateTimeFormatter SCOPE_DATE =
            DateTimeFormatter.ofPattern("yyyyMMdd").withZone(ZoneOffset.UTC);

    private AwsRequestSigner() {
    }

    /**
     * Returns the {@code X-Amz-Date} and {@code Authorization} headers a header-signed request
     * carries. {@code queryParameters} must be the parameters that will actually be sent, and
     * {@code body} the bytes that will actually be sent.
     */
    public static Map<String, String> signedHeaders(String httpMethod, String path,
                                                    Map<String, String> queryParameters,
                                                    String host, byte[] body,
                                                    String accessKeyId, String secretKey,
                                                    String region, String service, Instant signedAt)
            throws Exception {
        String amzDate = AMZ_DATE.format(signedAt);
        String scopeDate = SCOPE_DATE.format(signedAt);
        String credentialScope = scopeDate + "/" + region + "/" + service + "/aws4_request";
        String signedHeaderNames = "host;x-amz-date";

        String canonicalRequest = httpMethod + "\n"
                + path + "\n"
                + canonicalQueryString(queryParameters) + "\n"
                + "host:" + host + "\n"
                + "x-amz-date:" + amzDate + "\n"
                + "\n"
                + signedHeaderNames + "\n"
                + sha256Hex(body == null ? new byte[0] : body);

        String stringToSign = "AWS4-HMAC-SHA256\n"
                + amzDate + "\n"
                + credentialScope + "\n"
                + sha256Hex(canonicalRequest.getBytes(StandardCharsets.UTF_8));
        byte[] signingKey = signingKey(secretKey, scopeDate, region, service);
        String signature = hex(hmac(signingKey, stringToSign));

        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("X-Amz-Date", amzDate);
        headers.put("Authorization", "AWS4-HMAC-SHA256 "
                + "Credential=" + accessKeyId + "/" + credentialScope + ", "
                + "SignedHeaders=" + signedHeaderNames + ", "
                + "Signature=" + signature);
        return headers;
    }

    /** A form-encoded AWS Query body, in the order the signature covers it. */
    public static String formBody(Map<String, String> parameters) {
        StringBuilder body = new StringBuilder();
        for (Map.Entry<String, String> entry : new TreeMap<>(parameters).entrySet()) {
            if (!body.isEmpty()) {
                body.append('&');
            }
            body.append(uriEncode(entry.getKey())).append('=').append(uriEncode(entry.getValue()));
        }
        return body.toString();
    }

    private static String canonicalQueryString(Map<String, String> queryParameters) {
        if (queryParameters == null || queryParameters.isEmpty()) {
            return "";
        }
        StringBuilder canonical = new StringBuilder();
        for (Map.Entry<String, String> entry : new TreeMap<>(queryParameters).entrySet()) {
            if (!canonical.isEmpty()) {
                canonical.append('&');
            }
            canonical.append(uriEncode(entry.getKey())).append('=').append(uriEncode(entry.getValue()));
        }
        return canonical.toString();
    }

    private static byte[] signingKey(String secretKey, String date, String region, String service)
            throws Exception {
        byte[] kSecret = ("AWS4" + secretKey).getBytes(StandardCharsets.UTF_8);
        return hmac(hmac(hmac(hmac(kSecret, date), region), service), "aws4_request");
    }

    private static byte[] hmac(byte[] key, String data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }

    private static String sha256Hex(byte[] input) throws Exception {
        return hex(MessageDigest.getInstance("SHA-256").digest(input));
    }

    private static String hex(byte[] bytes) {
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            out.append(Character.forDigit((b >> 4) & 0xF, 16)).append(Character.forDigit(b & 0xF, 16));
        }
        return out.toString();
    }

    private static String uriEncode(String value) {
        StringBuilder encoded = new StringBuilder(value.length());
        for (byte raw : value.getBytes(StandardCharsets.UTF_8)) {
            int b = raw & 0xFF;
            char ch = (char) b;
            if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9')
                    || ch == '-' || ch == '.' || ch == '_' || ch == '~') {
                encoded.append(ch);
            } else {
                encoded.append('%')
                        .append(Character.toUpperCase(Character.forDigit((b >> 4) & 0xF, 16)))
                        .append(Character.toUpperCase(Character.forDigit(b & 0xF, 16)));
            }
        }
        return encoded.toString();
    }
}

package io.github.hectorvent.floci.core.common;

import org.jboss.logging.Logger;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * The one place Floci rebuilds an AWS SigV4 canonical request and compares the signature on it.
 *
 * <p>Every caller that has to decide whether a request really was signed by the holder of an
 * access key goes through here: the request filter that validates every signed request
 * ({@code SignatureValidationFilter}) and the execute-api data-plane authorizer
 * ({@code ExecuteApiSigV4Authorizer}). Keeping one implementation is the point — a second copy
 * is a second set of canonicalisation bugs, and canonicalisation bugs are either an outage
 * (a legitimate request refused) or a hole (a forged request accepted).
 *
 * <p>Both signing placements AWS accepts are handled: an {@code Authorization} header and a
 * presigned query string ({@code X-Amz-Algorithm=AWS4-HMAC-SHA256}). The caller supplies the
 * request through {@link Request} and the secret through {@link SecretLookup}; this class holds
 * no state and knows nothing about IAM, accounts, or the wire format of an error.
 */
public final class SigV4SignatureVerifier {

    private static final Logger LOG = Logger.getLogger(SigV4SignatureVerifier.class);

    public static final String ALGORITHM = "AWS4-HMAC-SHA256";
    public static final String TERMINATOR = "aws4_request";

    /** Where a temporary credential's session token rides: a header, or a presigned query parameter. */
    public static final String SECURITY_TOKEN = "X-Amz-Security-Token";

    private static final DateTimeFormatter AMZ_DATE =
            DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").withZone(ZoneOffset.UTC);

    /** AWS rejects a header-signed request whose {@code X-Amz-Date} is more than five minutes out. */
    public static final long MAX_CLOCK_SKEW_SECONDS = 300;

    /** Longest {@code X-Amz-Expires} AWS accepts on a presigned request (7 days). */
    public static final long MAX_PRESIGNED_EXPIRY_SECONDS = 604800;

    private SigV4SignatureVerifier() {
    }

    /** Why a request was not verified. Each caller maps this onto the wire error its protocol uses. */
    public enum Failure {
        /** Nothing on the request even claims to be SigV4-signed. */
        MISSING,
        /** Something claims to be SigV4-signed, but a part the signature needs is absent. */
        INCOMPLETE,
        /** The SigV4 credentials are present but unparsable, or not scoped as the caller requires. */
        MALFORMED,
        /** The credential names an access key this emulator has never issued, or has deactivated. */
        UNKNOWN_KEY,
        /** The credential is a session that has expired. */
        EXPIRED_CREDENTIAL,
        /** The signing timestamp is outside the accepted window, or a presigned URL has expired. */
        EXPIRED_SIGNATURE,
        /** The signature does not match the one derived from the caller's secret key. */
        MISMATCH
    }

    /** The {@code accessKeyId/date/region/service/aws4_request} a credential carries. */
    public record CredentialScope(String accessKeyId, String date, String region, String service) {

        public String scope() {
            return date + "/" + region + "/" + service + "/" + TERMINATOR;
        }

        /**
         * {@code credential} is expected already percent-decoded: a header credential is never
         * encoded, and JAX-RS decodes the presigned {@code X-Amz-Credential} before we see it.
         */
        public static CredentialScope parse(String credential) {
            if (credential == null) {
                return null;
            }
            String[] parts = credential.split("/");
            if (parts.length != 5 || !TERMINATOR.equals(parts[4])) {
                return null;
            }
            if (parts[0].isBlank() || parts[1].length() != 8 || parts[2].isBlank() || parts[3].isBlank()) {
                return null;
            }
            for (int index = 0; index < 8; index++) {
                if (!Character.isDigit(parts[1].charAt(index))) {
                    return null;
                }
            }
            return new CredentialScope(parts[0], parts[1], parts[2], parts[3].toLowerCase(Locale.ROOT));
        }
    }

    /** The SigV4 parts of a request, wherever the client put them. */
    public record SignedRequest(CredentialScope scope, String signedHeaders, String signature,
                                String amzDate, Long expiresSeconds, boolean presigned) {}

    /** The outcome of {@link #verify}: a {@code null} failure means the signature is genuine. */
    public record Result(Failure failure, String detail, SignedRequest signed) {

        public boolean verified() {
            return failure == null;
        }

        public static Result rejected(Failure failure, String detail, SignedRequest signed) {
            return new Result(failure, detail, signed);
        }
    }

    /** What the verifier needs of a request, however it reached the emulator. */
    public interface Request {

        String method();

        /** The path exactly as it went on the wire, before any host or route rewriting. */
        String rawPath();

        /** The query string exactly as it went on the wire, or null. */
        String rawQuery();

        /** The host the client signed, without a default port. */
        String host();

        String header(String name);

        String queryParameter(String name);

        /** The request body, or an empty array. Never read when the payload hash is a sentinel. */
        byte[] body();
    }

    /**
     * Resolves the secret backing an access key, or {@code null} when this is a credential the
     * caller will not authenticate. Failing closed here is the point: an access key that resolves
     * to itself as its own secret is a request anyone can self-sign.
     */
    public interface SecretLookup {

        String secretFor(String accessKeyId, String sessionToken);
    }

    /**
     * Reads the SigV4 parts off a request, or {@code null} when nothing on it claims to be signed.
     * A request that claims to be signed but is missing a part yields a {@link SignedRequest} whose
     * {@code scope} is null, which {@link #verify} reports as {@link Failure#INCOMPLETE}.
     */
    public static SignedRequest read(Request request) {
        boolean presigned = ALGORITHM.equals(request.queryParameter("X-Amz-Algorithm"));
        if (presigned) {
            return presignedRequest(request);
        }
        String authorization = request.header("Authorization");
        if (authorization == null || authorization.isBlank()) {
            return null;
        }
        String trimmed = authorization.trim();
        if (!trimmed.regionMatches(true, 0, ALGORITHM, 0, ALGORITHM.length())) {
            return null; // Bearer, Basic, or an AWS signing scheme this emulator does not verify
        }
        Map<String, String> parameters = new LinkedHashMap<>();
        for (String part : trimmed.substring(ALGORITHM.length()).split(",")) {
            int equals = part.indexOf('=');
            if (equals > 0) {
                parameters.put(part.substring(0, equals).trim(), part.substring(equals + 1).trim());
            }
        }
        String amzDate = request.header("X-Amz-Date");
        if (isBlank(amzDate)) {
            amzDate = request.header("Date");
        }
        return new SignedRequest(
                CredentialScope.parse(parameters.get("Credential")),
                lowerCase(parameters.get("SignedHeaders")),
                parameters.get("Signature"),
                amzDate,
                null,
                false);
    }

    private static SignedRequest presignedRequest(Request request) {
        String expires = request.queryParameter("X-Amz-Expires");
        Long expiresSeconds;
        try {
            expiresSeconds = isBlank(expires) ? null : Long.valueOf(expires.trim());
        } catch (NumberFormatException e) {
            expiresSeconds = null;
        }
        return new SignedRequest(
                CredentialScope.parse(request.queryParameter("X-Amz-Credential")),
                lowerCase(request.queryParameter("X-Amz-SignedHeaders")),
                request.queryParameter("X-Amz-Signature"),
                request.queryParameter("X-Amz-Date"),
                expiresSeconds,
                true);
    }

    /**
     * Verifies {@code signed} against {@code request}.
     *
     * @param expectedService the credential scope's service must be this one, or null to accept
     *                        whatever service the scope names (the signature covers it either way)
     * @param signedPath      the path the client signed, when route rewriting means it is not
     *                        {@link Request#rawPath()}; null to use the raw path
     * @param requireHost     whether {@code SignedHeaders} must cover {@code host}
     */
    public static Result verify(Request request, SignedRequest signed, SecretLookup lookup,
                                String expectedService, String signedPath, boolean requireHost) {
        if (signed == null) {
            return Result.rejected(Failure.MISSING, "request is not SigV4-signed", null);
        }
        try {
            return check(request, signed, lookup, expectedService, signedPath, requireHost);
        } catch (Exception e) {
            // A malformed credential, an unparsable date, an unreadable body: every one of these is
            // a request we could not verify, and an unverifiable request is not verified. Logged
            // rather than swallowed so an operational fault stays diagnosable.
            LOG.debugv(e, "SigV4 verification failed to complete: {0}", e.getMessage());
            return Result.rejected(Failure.MALFORMED, "signature could not be verified", signed);
        }
    }

    private static Result check(Request request, SignedRequest signed, SecretLookup lookup,
                                String expectedService, String signedPath, boolean requireHost)
            throws Exception {
        if (signed.scope() == null || isBlank(signed.signedHeaders())
                || isBlank(signed.signature()) || isBlank(signed.amzDate())) {
            return Result.rejected(Failure.INCOMPLETE, "SigV4 credentials are incomplete", signed);
        }
        CredentialScope scope = signed.scope();
        if (expectedService != null && !expectedService.equals(scope.service())) {
            return Result.rejected(Failure.MALFORMED,
                    "credential is scoped to service " + scope.service() + ", not " + expectedService, signed);
        }
        if (!signed.amzDate().startsWith(scope.date())) {
            return Result.rejected(Failure.MALFORMED,
                    "credential scope date does not match X-Amz-Date", signed);
        }
        if (requireHost && !containsHeader(signed.signedHeaders(), "host")) {
            return Result.rejected(Failure.MALFORMED, "SignedHeaders does not cover host", signed);
        }

        Instant signedAt = Instant.from(AMZ_DATE.parse(signed.amzDate()));
        Result expiry = checkExpiry(signedAt, signed.expiresSeconds(), signed.presigned(), signed);
        if (expiry != null) {
            return expiry;
        }

        String sessionToken = request.queryParameter(SECURITY_TOKEN);
        if (isBlank(sessionToken)) {
            sessionToken = request.header(SECURITY_TOKEN);
        }
        String secretKey = lookup.secretFor(scope.accessKeyId(), sessionToken);
        if (secretKey == null) {
            LOG.debugv("SigV4 request references a credential this emulator will not authenticate: {0}",
                    sanitizeForLog(scope.accessKeyId()));
            return Result.rejected(Failure.UNKNOWN_KEY, "access key is not registered", signed);
        }

        String payloadHash = payloadHash(request, signed);
        String canonicalHeaders = canonicalHeaders(signed.signedHeaders(), request);
        String canonicalQueryString = canonicalQueryString(request.rawQuery(), signed.presigned());
        byte[] signingKey = deriveSigningKey(secretKey, scope.date(), scope.region(), scope.service());

        String rawPath = signedPath != null ? signedPath : request.rawPath();
        for (String canonicalUri : canonicalUriCandidates(rawPath)) {
            String canonicalRequest = request.method() + "\n"
                    + canonicalUri + "\n"
                    + canonicalQueryString + "\n"
                    + canonicalHeaders + "\n"
                    + signed.signedHeaders() + "\n"
                    + payloadHash;
            String stringToSign = ALGORITHM + "\n"
                    + signed.amzDate() + "\n"
                    + scope.scope() + "\n"
                    + sha256Hex(canonicalRequest.getBytes(StandardCharsets.UTF_8));
            String expected = hexEncode(hmacSha256(signingKey, stringToSign));
            if (MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8),
                    signed.signature().getBytes(StandardCharsets.UTF_8))) {
                return new Result(null, null, signed);
            }
        }

        LOG.debugv("SigV4 signature mismatch for accessKey={0}", sanitizeForLog(scope.accessKeyId()));
        return Result.rejected(Failure.MISMATCH, "signature does not match", signed);
    }

    private static Result checkExpiry(Instant signedAt, Long expiresSeconds, boolean presigned,
                                      SignedRequest signed) {
        Instant now = Instant.now();
        if (presigned) {
            if (expiresSeconds == null || expiresSeconds < 1 || expiresSeconds > MAX_PRESIGNED_EXPIRY_SECONDS) {
                return Result.rejected(Failure.INCOMPLETE, "X-Amz-Expires is missing or out of range", signed);
            }
            if (now.isAfter(signedAt.plusSeconds(expiresSeconds))) {
                return Result.rejected(Failure.EXPIRED_SIGNATURE, "presigned request expired", signed);
            }
            // A presigned URL signed in the future is still a forgery attempt, not a slow clock.
            if (signedAt.isAfter(now.plusSeconds(MAX_CLOCK_SKEW_SECONDS))) {
                return Result.rejected(Failure.EXPIRED_SIGNATURE, "presigned request is not yet valid", signed);
            }
            return null;
        }
        if (Math.abs(now.getEpochSecond() - signedAt.getEpochSecond()) > MAX_CLOCK_SKEW_SECONDS) {
            return Result.rejected(Failure.EXPIRED_SIGNATURE,
                    "signature date " + AMZ_DATE.format(signedAt) + " is outside the accepted window", signed);
        }
        return null;
    }

    // ──────────────────────────── Canonical request ────────────────────────────

    /**
     * The canonical URI candidates a signer could have produced for this raw path. Non-S3 SigV4
     * URI-encodes each path segment a second time on top of the encoding already on the wire; for
     * an all-ASCII path the two forms are identical, so only paths carrying escapes produce a
     * second candidate. Trying both keeps a legitimately signed request from being rejected over
     * which convention its signer follows.
     */
    static List<String> canonicalUriCandidates(String rawPath) {
        String raw = isBlank(rawPath) ? "/" : rawPath;
        List<String> candidates = new ArrayList<>(2);
        candidates.add(raw);
        String[] segments = raw.split("/", -1);
        StringBuilder doubleEncoded = new StringBuilder();
        for (int i = 0; i < segments.length; i++) {
            if (i > 0) {
                doubleEncoded.append('/');
            }
            doubleEncoded.append(uriEncode(segments[i]));
        }
        if (!candidates.contains(doubleEncoded.toString())) {
            candidates.add(doubleEncoded.toString());
        }
        return candidates;
    }

    static String canonicalQueryString(String rawQuery, boolean dropSignature) {
        if (isBlank(rawQuery)) {
            return "";
        }
        List<String[]> pairs = new ArrayList<>();
        for (String pair : rawQuery.split("&")) {
            if (pair.isEmpty()) {
                continue;
            }
            int equals = pair.indexOf('=');
            String name = decodeQueryComponent(equals >= 0 ? pair.substring(0, equals) : pair);
            String value = decodeQueryComponent(equals >= 0 ? pair.substring(equals + 1) : "");
            if (dropSignature && "X-Amz-Signature".equals(name)) {
                continue;
            }
            pairs.add(new String[]{uriEncode(name), uriEncode(value)});
        }
        pairs.sort(Comparator.<String[], String>comparing(pair -> pair[0]).thenComparing(pair -> pair[1]));
        StringBuilder canonical = new StringBuilder();
        for (String[] pair : pairs) {
            if (!canonical.isEmpty()) {
                canonical.append('&');
            }
            canonical.append(pair[0]).append('=').append(pair[1]);
        }
        return canonical.toString();
    }

    private static String canonicalHeaders(String signedHeaders, Request request) {
        StringBuilder canonical = new StringBuilder();
        for (String name : signedHeaders.split(";")) {
            String value = "host".equals(name) ? request.host() : request.header(name);
            canonical.append(name).append(':').append(normalizeHeaderValue(value)).append('\n');
        }
        return canonical.toString();
    }

    /** SigV4 signers omit the default ports 80 and 443 from the signed host; any other port is kept. */
    public static String withoutDefaultPort(String host) {
        if (host == null) {
            return "";
        }
        int colon = host.lastIndexOf(':');
        // A colon inside IPv6 brackets is part of the address, not a port separator.
        if (colon < 0 || colon < host.lastIndexOf(']')) {
            return host;
        }
        if (host.indexOf(':') != colon && !host.startsWith("[")) {
            return host; // bare IPv6 literal without brackets carries no port
        }
        String port = host.substring(colon + 1);
        return "80".equals(port) || "443".equals(port) ? host.substring(0, colon) : host;
    }

    private static String normalizeHeaderValue(String value) {
        return value == null ? "" : value.trim().replaceAll("\\s+", " ");
    }

    /**
     * The payload hash the canonical request must carry.
     *
     * <p>A literal {@code x-amz-content-sha256} is deliberately <em>not</em> taken on trust: the
     * body is hashed instead. For an honest request the two are equal, and for a tampered one they
     * are not, which turns a swapped body into a signature mismatch. Trusting the header would let
     * a caller keep a valid signature over a body they had replaced, since the header value the
     * signer hashed would still be the one presented.
     *
     * <p>The sentinels ({@code UNSIGNED-PAYLOAD}, the {@code STREAMING-*} forms) mean the caller
     * chose not to sign the body, and are honoured only when {@code x-amz-content-sha256} is itself
     * in {@code SignedHeaders}: that is, when the choice is covered by the signature. A presigned
     * request is unsigned-payload by convention; every AWS presigner emits it that way.
     */
    private static String payloadHash(Request request, SignedRequest signed) throws Exception {
        String declared = request.header("x-amz-content-sha256");
        if (declared != null && !declared.isBlank()
                && containsHeader(signed.signedHeaders(), "x-amz-content-sha256")
                && !isSha256Hex(declared.trim())) {
            return declared.trim();
        }
        if (signed.presigned()) {
            String presignedDeclared = request.queryParameter("X-Amz-Content-Sha256");
            if (presignedDeclared != null && !presignedDeclared.isBlank() && !isSha256Hex(presignedDeclared.trim())) {
                return presignedDeclared.trim();
            }
            return "UNSIGNED-PAYLOAD";
        }
        byte[] body = request.body();
        return sha256Hex(body == null ? new byte[0] : body);
    }

    static boolean containsHeader(String signedHeaders, String name) {
        if (signedHeaders == null) {
            return false;
        }
        for (String header : signedHeaders.split(";")) {
            if (name.equals(header)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isSha256Hex(String value) {
        if (value.length() != 64) {
            return false;
        }
        for (int index = 0; index < value.length(); index++) {
            if (Character.digit(value.charAt(index), 16) < 0) {
                return false;
            }
        }
        return true;
    }

    // ──────────────────────────── Crypto and encoding helpers ────────────────────────────

    public static byte[] deriveSigningKey(String secretKey, String date, String region, String service)
            throws Exception {
        byte[] kSecret = ("AWS4" + secretKey).getBytes(StandardCharsets.UTF_8);
        byte[] kDate = hmacSha256(kSecret, date);
        byte[] kRegion = hmacSha256(kDate, region);
        byte[] kService = hmacSha256(kRegion, service);
        return hmacSha256(kService, TERMINATOR);
    }

    public static byte[] hmacSha256(byte[] key, String data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }

    public static String sha256Hex(byte[] input) throws Exception {
        return hexEncode(MessageDigest.getInstance("SHA-256").digest(input));
    }

    public static String hexEncode(byte[] bytes) {
        StringBuilder hex = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            hex.append(Character.forDigit((b >> 4) & 0xF, 16)).append(Character.forDigit(b & 0xF, 16));
        }
        return hex.toString();
    }

    /** RFC 3986 percent-encoding as SigV4 defines it: {@code /} is escaped, {@code -._~} are not. */
    static String uriEncode(String value) {
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

    /**
     * Percent-decodes a query-string component without {@code URLDecoder}'s form-encoding rule that
     * a literal {@code +} means a space: SigV4 signers escape a space as {@code %20}, so a raw
     * {@code +} on the wire is a plus sign and re-encoding it as a space would break the signature.
     */
    private static String decodeQueryComponent(String value) {
        if (value == null) {
            return "";
        }
        return URLDecoder.decode(value.replace("+", "%2B"), StandardCharsets.UTF_8);
    }

    private static String lowerCase(String value) {
        return value == null ? null : value.toLowerCase(Locale.ROOT);
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    /** Strips control characters from attacker-controlled values before they reach a log line. */
    public static String sanitizeForLog(String value) {
        return value == null ? null : value.replaceAll("\\p{Cntrl}", "");
    }
}

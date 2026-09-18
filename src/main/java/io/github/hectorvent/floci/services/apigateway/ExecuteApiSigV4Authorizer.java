package io.github.hectorvent.floci.services.apigateway;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.RequestHost;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.core.common.SigV4SignatureVerifier;
import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.iam.model.AccessKey;
import io.github.hectorvent.floci.services.iam.model.IamUser;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.UriInfo;
import org.jboss.logging.Logger;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Verifies the SigV4 signature on an execute-api data-plane request, so a route or method whose
 * {@code authorizationType} is {@code AWS_IAM} actually requires a signed caller instead of merely
 * recording that it does.
 *
 * <p>The canonical request is rebuilt by {@link SigV4SignatureVerifier}, the one place Floci does
 * that; this class supplies the execute-api specifics — the signed path after route rewriting, the
 * service the credential must be scoped to, the session-token rule, and the caller identity that
 * dispatch puts on the proxy event.
 *
 * <h2>Deliberate deviations from real AWS</h2>
 * <ul>
 *   <li><strong>No authorization, only authentication.</strong> A valid signature from any known
 *       access key is accepted; {@code execute-api:Invoke} is not evaluated against the caller's
 *       IAM policies or a resource policy. Floci's IAM policy evaluation is opt-in and off by
 *       default, so gating the data plane on it would make the common case unusable.</li>
 *   <li><strong>The credential scope's region is not pinned</strong> to the API's region. Floci
 *       resolves a request's region <em>from</em> that scope, so pinning it would be circular.</li>
 *   <li>The well-known local-dev {@code test}/{@code test} credential pair is honoured while IAM
 *       enforcement is off, mirroring the identical fallback in {@code S3Service},
 *       {@code PreSignedUrlFilter} and {@code S3PostPolicySigner}. With
 *       {@code floci.services.iam.enforcement-enabled} on it is refused like any other
 *       unregistered key: the emulator's one default credential under enforcement is the seeded
 *       deployer principal ({@code floci.services.iam.seed-deployer-principal}). No other
 *       unregistered access key is accepted either way.</li>
 * </ul>
 */
@ApplicationScoped
public class ExecuteApiSigV4Authorizer {

    private static final Logger LOG = Logger.getLogger(ExecuteApiSigV4Authorizer.class);

    private static final String SIGNING_SERVICE = "execute-api";

    private static final String LEGACY_ACCESS_KEY_ID = "test";
    private static final String LEGACY_SECRET_KEY = "test";

    private final IamService iamService;
    private final RegionResolver regionResolver;
    private final EmulatorConfig config;

    @Inject
    public ExecuteApiSigV4Authorizer(IamService iamService, RegionResolver regionResolver,
                                     EmulatorConfig config) {
        this.iamService = iamService;
        this.regionResolver = regionResolver;
        this.config = config;
    }

    /** Test constructor: no {@link EmulatorConfig}, so IAM enforcement reads as off. */
    public ExecuteApiSigV4Authorizer(IamService iamService, RegionResolver regionResolver) {
        this(iamService, regionResolver, null);
    }

    /** Why a request was rejected. Dispatch maps this onto the wire error its API type uses. */
    public enum Failure {
        /** Nothing on the request even claims to be SigV4-signed. */
        MISSING,
        /** SigV4 credentials are present but unparsable, incomplete, or not scoped to execute-api. */
        MALFORMED,
        /** The credential names an access key this emulator has never issued. */
        UNKNOWN_KEY,
        /** The signing timestamp is outside the accepted window, or a presigned URL has expired. */
        EXPIRED,
        /** The signature does not match the one derived from the caller's secret key. */
        MISMATCH
    }

    /**
     * The caller behind a verified signature, as API Gateway surfaces it on the proxy event
     * ({@code requestContext.identity} on REST, {@code requestContext.authorizer.iam} on HTTP).
     */
    public record CallerIdentity(String accessKey, String accountId, String userArn, String userId) {}

    /** A {@code null} failure means authorized, mirroring the authorizer results in dispatch. */
    public record Result(Failure failure, String detail, CallerIdentity identity) {

        public boolean authorized() {
            return failure == null;
        }

        static Result rejected(Failure failure, String detail) {
            return new Result(failure, detail, null);
        }
    }

    public Result authorize(String httpMethod, HttpHeaders headers, UriInfo uriInfo, byte[] body,
                            String signedRequestPath) {
        SigV4SignatureVerifier.Request request = new ExecuteApiRequest(httpMethod, headers, uriInfo, body);
        SigV4SignatureVerifier.SignedRequest signed = SigV4SignatureVerifier.read(request);
        if (signed == null) {
            return Result.rejected(Failure.MISSING, "request is not SigV4-signed");
        }

        SigV4SignatureVerifier.Result result = SigV4SignatureVerifier.verify(
                request, signed, this::resolveSecretKey, SIGNING_SERVICE, signedRequestPath, true);
        if (!result.verified()) {
            return Result.rejected(map(result.failure()), result.detail());
        }

        String accessKeyId = result.signed().scope().accessKeyId();
        Result sessionToken = checkSessionToken(accessKeyId, headers, uriInfo.getQueryParameters());
        if (sessionToken != null) {
            return sessionToken;
        }
        return new Result(null, null, resolveIdentity(accessKeyId));
    }

    /**
     * Maps the shared verifier's outcome onto this authorizer's published failures. Both
     * "incomplete" and "malformed" have always surfaced here as {@link Failure#MALFORMED}, and both
     * kinds of staleness as {@link Failure#EXPIRED}, so dispatch and the SDKs see no change.
     */
    private static Failure map(SigV4SignatureVerifier.Failure failure) {
        return switch (failure) {
            case MISSING -> Failure.MISSING;
            case INCOMPLETE, MALFORMED -> Failure.MALFORMED;
            case UNKNOWN_KEY -> Failure.UNKNOWN_KEY;
            case EXPIRED_CREDENTIAL, EXPIRED_SIGNATURE -> Failure.EXPIRED;
            case MISMATCH -> Failure.MISMATCH;
        };
    }

    /**
     * Resolves the secret backing an access key, or {@code null} when the credential is one this
     * emulator will not authenticate. Failing closed here is the point: an earlier revision of the
     * ElastiCache and RDS validators fell back to the access key id as its own secret, which let
     * any caller self-sign a request.
     *
     * <p>{@code findSecretKey} screens out an expired session and an inactive access key on its
     * own. {@code resolveAccountId} is required on top of it because a verified caller has to be
     * attributed to an account to reach the integration at all: a credential this emulator cannot
     * place in one is not something to authenticate. It rejects the same expired AssumeRole
     * credential and deactivated long-term key a second time, which is why those cases stay
     * covered whichever of the two gates moves.
     *
     * <p>The session token a temporary credential carries is checked separately, by
     * {@link #checkSessionToken}.
     */
    private String resolveSecretKey(String accessKeyId, String sessionToken) {
        if (LEGACY_ACCESS_KEY_ID.equals(accessKeyId)) {
            return iamEnforcementEnabled() ? null : LEGACY_SECRET_KEY;
        }
        String secretKey = iamService.findSecretKey(accessKeyId).orElse(null);
        if (secretKey == null) {
            return null;
        }
        if (iamService.resolveAccountId(accessKeyId).isEmpty()) {
            LOG.debugv("execute-api request uses an expired or inactive credential: accessKey={0}",
                    SigV4SignatureVerifier.sanitizeForLog(accessKeyId));
            return null;
        }
        return secretKey;
    }

    private boolean iamEnforcementEnabled() {
        return config != null && config.services().iam().enforcementEnabled();
    }

    /**
     * Rejects a temporary credential that does not present the session token Floci issued with it,
     * returning {@code null} when there is nothing to object to.
     *
     * <p>The secret alone is not the whole credential. AWS requires the session token on every
     * request made with temporary credentials precisely because it is what confirms the credential
     * is live and genuinely STS-issued, so accepting an {@code ASIA...} key on its secret alone
     * lets an incomplete credential through a route that is supposed to demand a complete one.
     *
     * <p>The token is compared against the value recorded at mint time rather than merely required
     * to be present, so a fabricated token fails as well as a missing one. Presence is all that can
     * be demanded of a session stored before Floci recorded tokens: {@code findSessionToken} is
     * empty there, and rejecting it would lock out a credential that is otherwise perfectly valid.
     * {@code findSecretKey(accessKeyId, sessionToken)} is the stricter one-step alternative, which
     * this deliberately does not use because it cannot tell that case apart from a real mismatch.
     *
     * <p>Folding the token into the canonical request is deliberately not required. Whether a
     * service covers it by {@code SignedHeaders} or appends it after signing is service-specific in
     * SigV4, and comparing against the issued value binds the token regardless of where it rode.
     */
    private Result checkSessionToken(String accessKeyId, HttpHeaders headers,
                                     MultivaluedMap<String, String> queryParameters) {
        if (!IamService.isTemporaryAccessKey(accessKeyId)) {
            return null;
        }
        String presented = queryParameters.getFirst(SigV4SignatureVerifier.SECURITY_TOKEN);
        if (isBlank(presented) && headers != null) {
            presented = headers.getHeaderString(SigV4SignatureVerifier.SECURITY_TOKEN);
        }
        if (isBlank(presented)) {
            LOG.debugv("execute-api request uses temporary credential accessKey={0} with no {1}",
                    SigV4SignatureVerifier.sanitizeForLog(accessKeyId),
                    SigV4SignatureVerifier.SECURITY_TOKEN);
            return Result.rejected(Failure.UNKNOWN_KEY, "temporary credential presents no session token");
        }
        String issued = iamService.findSessionToken(accessKeyId).orElse(null);
        if (issued == null) {
            return null;
        }
        if (!MessageDigest.isEqual(issued.getBytes(StandardCharsets.UTF_8),
                presented.getBytes(StandardCharsets.UTF_8))) {
            LOG.debugv("execute-api request presents a session token that does not match the one"
                    + " issued for accessKey={0}", SigV4SignatureVerifier.sanitizeForLog(accessKeyId));
            return Result.rejected(Failure.UNKNOWN_KEY, "session token does not match the issued credential");
        }
        return null;
    }

    /**
     * Builds the caller for a signature that already verified. The {@code orElseGet} fallbacks are
     * reachable only for the legacy {@code test} credential: {@link #resolveSecretKey} has proved
     * every other accepted key resolves to a live account.
     */
    private CallerIdentity resolveIdentity(String accessKeyId) {
        String accountId = iamService.resolveAccountId(accessKeyId)
                .orElseGet(regionResolver::getAccountId);
        String userArn = iamService.resolveCallerArn(accessKeyId)
                .orElseGet(() -> "arn:aws:iam::" + accountId + ":root");
        String userId = iamService.findAccessKey(accessKeyId)
                .map(AccessKey::getUserName)
                .flatMap(iamService::findUser)
                .map(IamUser::getUserId)
                .orElse(accessKeyId);
        return new CallerIdentity(accessKeyId, accountId, userArn, userId);
    }

    /** The execute-api request as the shared verifier reads it. */
    private record ExecuteApiRequest(String httpMethod, HttpHeaders headers, UriInfo uriInfo, byte[] body)
            implements SigV4SignatureVerifier.Request {

        @Override
        public String method() {
            return httpMethod;
        }

        @Override
        public String rawPath() {
            return uriInfo.getRequestUri().getRawPath();
        }

        @Override
        public String rawQuery() {
            return uriInfo.getRequestUri().getRawQuery();
        }

        /**
         * The {@code host} value the client signed: the request host as the client sent it, the
         * {@code Host} header under HTTP/1.1 or the {@code :authority} under HTTP/2, read through
         * {@link RequestHost}.
         */
        @Override
        public String host() {
            return SigV4SignatureVerifier.withoutDefaultPort(
                    String.valueOf(RequestHost.of(headers, uriInfo.getRequestUri())));
        }

        @Override
        public String header(String name) {
            return headers == null ? null : headers.getHeaderString(name);
        }

        @Override
        public String queryParameter(String name) {
            return uriInfo.getQueryParameters().getFirst(name);
        }
    }

    static String withoutDefaultPort(String host) {
        return SigV4SignatureVerifier.withoutDefaultPort(host);
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}

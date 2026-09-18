package io.github.hectorvent.floci.core.common;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.services.cloudfront.CloudFrontDistributionFilter;
import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.s3.S3VirtualHostFilter;
import jakarta.annotation.Priority;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;
import org.jboss.logging.Logger;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.List;
import java.util.UUID;

/**
 * Validates the SigV4 signature on every signed request, for access keys and sessions alike, when
 * {@code floci.auth.validate-signatures} is on.
 *
 * <p>Without this, the access key on a request is a claim and nothing more: every downstream gate —
 * {@link IamEnforcementFilter}, S3's own authorization, the S3 presigned paths — reads the key out
 * of {@code Authorization} or {@code X-Amz-Credential} and takes the caller's word for it, so any
 * client can act as any principal simply by naming it. Turning the flag on makes the key something
 * the caller has to prove, which is what makes IAM enforcement above it mean anything.
 *
 * <p>Runs at {@link Priorities#AUTHENTICATION}: after {@link AccountContextFilter}, which resolves
 * the request's account and region from the same credential, and before {@link IamEnforcementFilter},
 * so an unproven credential never reaches policy evaluation. The request body is buffered and the
 * entity stream replaced, the same way {@code IamActionRegistry.readFormAction} and
 * {@code ResourceArnBuilder.readJsonBody} already do below it, so both keep working unchanged.
 * A body is read only when the payload hash the client signed is a real digest: {@code UNSIGNED-PAYLOAD}
 * and the {@code STREAMING-*} forms are honoured as AWS honours them, and a presigned request is
 * unsigned-payload by convention, so neither reads the body at all.
 *
 * <p>What is exempt, and why:
 * <ul>
 *   <li><strong>A request carrying no AWS SigV4 credential.</strong> There is no signature to
 *       validate. Anonymous S3 reads, a public CloudFront object, the health endpoint and the
 *       sign-in UI all arrive this way and stay exactly as they are; whether they are allowed is
 *       decided where it already is, by the bucket's public-access rules or by the route.</li>
 *   <li><strong>Floci's own non-AWS routes</strong> — {@code /health}, {@code /q/}, {@code /_floci/},
 *       {@code /_aws/}, {@code /_api/}, {@code /_cloudfront/}, {@code /_emrserverless/} and the
 *       CloudFormation {@code /cfn-response} callback. These are the emulator's inspection, UI and
 *       internal endpoints; they are not AWS API surface and no SDK signs them.</li>
 *   <li><strong>Requests scoped to {@code execute-api}.</strong> The API Gateway data plane has its
 *       own authorizer, {@code ExecuteApiSigV4Authorizer}, which verifies the same signature against
 *       the path the client signed <em>before</em> route rewriting. Checking it twice, once against
 *       the rewritten path, would refuse every legitimately signed call.</li>
 *   <li><strong>Content Floci is serving on behalf of a distribution or a user pool's custom
 *       domain.</strong> An {@code Authorization} header on such a request belongs to the origin or
 *       to the application, not to Floci, and is forwarded, not verified.</li>
 * </ul>
 */
@Provider
@ApplicationScoped
@Priority(Priorities.AUTHENTICATION)
public class SignatureValidationFilter implements ContainerRequestFilter {

    private static final Logger LOG = Logger.getLogger(SignatureValidationFilter.class);

    /** Floci's own routes: inspection, UI, internal callbacks. No SDK signs any of them. */
    private static final List<String> EXEMPT_PATH_PREFIXES = List.of(
            "/health", "/q/", "/_floci/", "/_aws/", "/_api/", "/_cloudfront/",
            "/_emrserverless/", "/cfn-response");

    /** The API Gateway data plane verifies its own signature, against the pre-rewrite path. */
    private static final String EXECUTE_API = "execute-api";

    private final EmulatorConfig config;
    private final IamService iamService;

    @Inject
    public SignatureValidationFilter(EmulatorConfig config, IamService iamService) {
        this.config = config;
        this.iamService = iamService;
    }

    @Override
    public void filter(ContainerRequestContext ctx) {
        if (!config.auth().validateSignatures()) {
            return;
        }
        if (isExemptRoute(ctx)) {
            return;
        }

        JaxRsRequest request = new JaxRsRequest(ctx);
        SigV4SignatureVerifier.SignedRequest signed = SigV4SignatureVerifier.read(request);
        if (signed == null) {
            return; // nothing claims to be signed: an anonymous request, decided further down
        }
        if (signed.scope() != null && EXECUTE_API.equals(signed.scope().service())) {
            return;
        }

        SigV4SignatureVerifier.Result result = SigV4SignatureVerifier.verify(
                request, signed, this::secretFor, null, null, false);
        request.restoreEntityStream();
        if (result.verified()) {
            return;
        }

        String service = signed.scope() == null ? null : signed.scope().service();
        SigV4SignatureVerifier.Failure failure = expiredSessionInstead(result.failure(), signed);
        LOG.infov("Signature validation refused {0} {1}: {2}",
                ctx.getMethod(), SigV4SignatureVerifier.sanitizeForLog(ctx.getUriInfo().getPath()),
                result.detail());
        ctx.abortWith(refusal(failure, result.detail(), service, ctx.getMediaType()));
    }

    /**
     * The strict lookup, for access keys and sessions alike: an access key that is not active, a
     * session that has lapsed, and a session token that is not the one Floci issued with the key
     * all resolve to nothing, and nothing is refused.
     */
    private String secretFor(String accessKeyId, String sessionToken) {
        return iamService.findSecretKey(accessKeyId, sessionToken).orElse(null);
    }

    /**
     * A temporary credential whose session has lapsed is {@code ExpiredToken} on AWS, not
     * {@code InvalidClientTokenId}: the client is told to refresh rather than to check its key.
     */
    private SigV4SignatureVerifier.Failure expiredSessionInstead(SigV4SignatureVerifier.Failure failure,
                                                                 SigV4SignatureVerifier.SignedRequest signed) {
        if (failure != SigV4SignatureVerifier.Failure.UNKNOWN_KEY || signed.scope() == null) {
            return failure;
        }
        return iamService.hasExpiredSession(signed.scope().accessKeyId())
                ? SigV4SignatureVerifier.Failure.EXPIRED_CREDENTIAL
                : failure;
    }

    private static boolean isExemptRoute(ContainerRequestContext ctx) {
        if (ctx.getProperty(CloudFrontDistributionFilter.ROUTED_PROPERTY) != null
                || ctx.getProperty(AccountContextFilter.PINNED_ACCOUNT_PROPERTY) != null) {
            return true;
        }
        String path = ctx.getUriInfo().getPath();
        if (path == null) {
            return false;
        }
        String normalized = path.startsWith("/") ? path : "/" + path;
        for (String prefix : EXEMPT_PATH_PREFIXES) {
            if (normalized.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    // ──────────────────────────── Wire errors ────────────────────────────

    /**
     * The error AWS gives for the protocol the request was made in. An SDK hard-fails on the wrong
     * shape — an XML parser on a leading <code>{</code>, a JSON parser on a <code>&lt;</code> — so
     * the shape is picked the same way {@link IamEnforcementFilter} picks its AccessDenied shape:
     * S3 by its credential scope, AWS Query by a form-encoded body, JSON otherwise.
     */
    static Response refusal(SigV4SignatureVerifier.Failure failure, String detail,
                            String credentialScope, MediaType requestMediaType) {
        boolean s3 = "s3".equals(credentialScope);
        boolean query = !s3 && isFormEncoded(requestMediaType);
        String code = code(failure, s3, query);
        int status = failure == SigV4SignatureVerifier.Failure.INCOMPLETE ? 400 : 403;
        String message = message(failure, detail);
        if (s3) {
            return s3Xml(status, code, message);
        }
        if (query) {
            return queryXml(status, code, message);
        }
        return json(status, code, message);
    }

    /**
     * AWS's own error code per protocol, as a client sees it: S3 answers
     * {@code SignatureDoesNotMatch}/{@code InvalidAccessKeyId}, the Query services
     * {@code SignatureDoesNotMatch}/{@code IncompleteSignature}/{@code InvalidClientTokenId}/
     * {@code ExpiredToken}, and the JSON services the {@code *Exception} spellings of the same.
     */
    private static String code(SigV4SignatureVerifier.Failure failure, boolean s3, boolean query) {
        return switch (failure) {
            case MISSING, INCOMPLETE, MALFORMED -> s3 ? "AccessDenied" : "IncompleteSignature";
            case UNKNOWN_KEY -> s3 ? "InvalidAccessKeyId" : "InvalidClientTokenId";
            case EXPIRED_CREDENTIAL -> s3 ? "ExpiredToken" : (query ? "ExpiredToken" : "ExpiredTokenException");
            case EXPIRED_SIGNATURE -> s3 ? "AccessDenied" : (query ? "SignatureDoesNotMatch" : "InvalidSignatureException");
            case MISMATCH -> s3 || query ? "SignatureDoesNotMatch" : "InvalidSignatureException";
        };
    }

    private static String message(SigV4SignatureVerifier.Failure failure, String detail) {
        return switch (failure) {
            case UNKNOWN_KEY -> "The AWS Access Key Id you provided does not exist in our records.";
            case MISMATCH -> "The request signature we calculated does not match the signature you"
                    + " provided. Check your AWS Secret Access Key and signing method.";
            case EXPIRED_SIGNATURE -> "Request has expired.";
            case EXPIRED_CREDENTIAL -> "The security token included in the request is expired.";
            default -> detail == null ? "The request signature is incomplete." : detail;
        };
    }

    private static boolean isFormEncoded(MediaType mt) {
        return mt != null
                && "application".equalsIgnoreCase(mt.getType())
                && "x-www-form-urlencoded".equalsIgnoreCase(mt.getSubtype());
    }

    private static Response s3Xml(int status, String code, String message) {
        String xml = new XmlBuilder()
                .raw("<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
                .start("Error")
                  .elem("Code", code)
                  .elem("Message", message)
                  .elem("RequestId", UUID.randomUUID().toString())
                .end("Error")
                .build();
        return Response.status(status).type(MediaType.APPLICATION_XML).entity(xml).build();
    }

    private static Response queryXml(int status, String code, String message) {
        String xml = new XmlBuilder()
                .start("ErrorResponse")
                  .start("Error")
                    .elem("Type", "Sender")
                    .elem("Code", code)
                    .elem("Message", message)
                  .end("Error")
                  .elem("RequestId", UUID.randomUUID().toString())
                .end("ErrorResponse")
                .build();
        return Response.status(status).type(MediaType.APPLICATION_XML).entity(xml).build();
    }

    private static Response json(int status, String code, String message) {
        String body = "{\"__type\":\"" + code + "\",\"message\":\"" + message + "\"}";
        return Response.status(status).type(MediaType.APPLICATION_JSON).entity(body).build();
    }

    // ──────────────────────────── The request, as the verifier reads it ────────────────────────────

    /**
     * Reads the request as the client signed it. Where a {@code @PreMatching} filter rewrote the
     * URI — S3's virtual-host form, {@code bucket.s3.localhost/key} becoming {@code /bucket/key} —
     * the original is what the signature covers, so that is what is read.
     */
    private static final class JaxRsRequest implements SigV4SignatureVerifier.Request {

        private final ContainerRequestContext ctx;
        private final URI signedUri;
        private byte[] body;

        private JaxRsRequest(ContainerRequestContext ctx) {
            this.ctx = ctx;
            this.signedUri = ctx.getProperty(S3VirtualHostFilter.ORIGINAL_REQUEST_URI_PROPERTY) instanceof URI uri
                    ? uri
                    : ctx.getUriInfo().getRequestUri();
        }

        @Override
        public String method() {
            return ctx.getMethod();
        }

        @Override
        public String rawPath() {
            return signedUri.getRawPath();
        }

        @Override
        public String rawQuery() {
            return signedUri.getRawQuery();
        }

        @Override
        public String host() {
            return SigV4SignatureVerifier.withoutDefaultPort(RequestHost.of(ctx, signedUri));
        }

        @Override
        public String header(String name) {
            return ctx.getHeaderString(name);
        }

        @Override
        public String queryParameter(String name) {
            return ctx.getUriInfo().getQueryParameters().getFirst(name);
        }

        @Override
        public byte[] body() {
            if (body != null) {
                return body;
            }
            InputStream in = ctx.getEntityStream();
            if (in == null) {
                body = new byte[0];
                return body;
            }
            try {
                body = in.readAllBytes();
            } catch (IOException e) {
                LOG.debugv(e, "Failed to buffer request body for signature validation");
                body = new byte[0];
            }
            return body;
        }

        /** Hands the buffered body back to the resource, so nothing below sees a consumed stream. */
        private void restoreEntityStream() {
            if (body != null) {
                ctx.setEntityStream(new ByteArrayInputStream(body));
            }
        }
    }
}

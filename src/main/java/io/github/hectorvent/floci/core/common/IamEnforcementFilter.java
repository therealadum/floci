package io.github.hectorvent.floci.core.common;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.services.cloudtrail.CloudTrailService;
import io.github.hectorvent.floci.services.iam.IamActionRegistry;
import io.github.hectorvent.floci.services.iam.IamPolicyEvaluator;
import io.github.hectorvent.floci.services.iam.IamPolicyEvaluator.Decision;
import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.iam.OrganizationProvider;
import io.github.hectorvent.floci.services.iam.ResourceArnBuilder;
import io.github.hectorvent.floci.services.iam.ResourcePolicyLookup;
import io.github.hectorvent.floci.services.iam.ScpProvider;
import io.github.hectorvent.floci.services.iam.model.AccountOrganization;
import io.github.hectorvent.floci.services.iam.model.CallerContext;
import io.github.hectorvent.floci.services.iam.model.RequestPrincipal;
import io.github.hectorvent.floci.services.iam.model.ResourcePolicies;
import io.quarkus.vertx.http.runtime.CurrentVertxRequest;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;
import org.jboss.logging.Logger;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * JAX-RS filter that enforces IAM policies on every incoming request when
 * {@code floci.services.iam.enforcement-enabled = true}.
 *
 * <p>With enforcement on, nothing is allowed by default. The request is let through only when:
 * <ul>
 *   <li>Enforcement is disabled (the default), when nothing here runs at all</li>
 *   <li>The request carries no AWS SigV4 credential, so there is no principal to evaluate and the
 *       route decides for itself (an anonymous S3 read, a Bearer-token UI call)</li>
 *   <li>The action is {@code sts:GetCallerIdentity}, which AWS allows without permissions</li>
 *   <li>The caller's policies allow the action on every resource the request names</li>
 * </ul>
 *
 * <p>What was once allowed and is now refused: an action {@link IamActionRegistry} cannot name, an
 * access key the account never issued, a session that has expired, a session carrying no role, and
 * the well-known {@code test} credential, which is a root stand-in only while enforcement is off.
 * Under enforcement the emulator's one default credential is the seeded deployer principal
 * ({@code floci.services.iam.seed-deployer-principal}), which is a real IAM user with a real secret.
 * The account-root principal — a bare 12-digit account-id access key — keeps full access, bounded
 * by service control policies, as it has on AWS.
 *
 * <p>Evaluates the caller's identity policies, optional session policy, optional permissions
 * boundary, and the resource's own policies. The resource policies come from
 * {@link ResourcePolicyLookup}, one lookup from a resource ARN to whatever policies are attached
 * to it, resolved lazily so IAM depends on no service that holds one. A service joins that lookup
 * by adding a {@code ResourcePolicySource} beside itself; nothing here changes.
 *
 * <p>Reads the signing credential from either the {@code Authorization} header or, for a
 * presigned URL, the {@code X-Amz-Credential} query parameter - both request shapes get the
 * same policy evaluation. A presigned POST form carries its credential in the multipart body,
 * which is unavailable at this JAX-RS filter stage; that shape is authorized separately via
 * {@link #authorizeAdditionalResource} once {@code S3Controller} has parsed the form fields.
 */
@Provider
@ApplicationScoped
public class IamEnforcementFilter implements ContainerRequestFilter {

    private static final Logger LOG = Logger.getLogger(IamEnforcementFilter.class);

    /** Extracts the credential-scope service name (e.g. "s3", "lambda"). */
    private static final Pattern SERVICE_PATTERN =
            Pattern.compile("Credential=\\S+/\\d{8}/[^/]+/([^/]+)/");

    /**
     * Implicit identity policy for the account-root principal: full access, bounded only by SCPs.
     * The account root is not a registered IAM identity, so it has no stored identity policy.
     */
    private static final String ROOT_ALLOW_ALL =
            "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}";

    /**
     * The services AWS supports resource control policies for, by credential scope. AWS names a
     * closed list rather than every service; this emulator carries no vendored copy of it, so the
     * five AWS documents today are named here and a sixth is added when AWS adds one.
     */
    private static final Set<String> RESOURCE_CONTROL_POLICY_SCOPES =
            Set.of("s3", "sts", "kms", "sqs", "secretsmanager");

    /** An IAM role under this path is a service-linked role, which resource control policies exempt. */
    private static final String SERVICE_LINKED_ROLE_PATH = ":role/aws-service-role/";

    private final EmulatorConfig config;
    private final AccountResolver accountResolver;
    private final IamService iamService;
    private final IamPolicyEvaluator evaluator;
    private final IamActionRegistry actionRegistry;
    private final ResourceArnBuilder arnBuilder;
    private final RequestContext requestContext;
    private final IamConditionContextResolver conditionContextResolver;
    private final CloudTrailService cloudTrailService;
    private final CurrentVertxRequest currentVertxRequest;
    private final ResolvedServiceCatalog catalog;
    private final Instance<ScpProvider> scpProvider;
    private final Instance<OrganizationProvider> organizationProvider;
    private final SessionAccountLookup sessionAccountLookup;
    private final ResourcePolicyLookup resourcePolicyLookup;

    @Inject
    public IamEnforcementFilter(EmulatorConfig config,
                                AccountResolver accountResolver,
                                IamService iamService,
                                IamPolicyEvaluator evaluator,
                                IamActionRegistry actionRegistry,
                                ResourceArnBuilder arnBuilder,
                                RequestContext requestContext,
                                IamConditionContextResolver conditionContextResolver,
                                CloudTrailService cloudTrailService,
                                CurrentVertxRequest currentVertxRequest,
                                ResolvedServiceCatalog catalog,
                                Instance<ScpProvider> scpProvider,
                                Instance<OrganizationProvider> organizationProvider,
                                SessionAccountLookup sessionAccountLookup,
                                ResourcePolicyLookup resourcePolicyLookup) {
        this.config = config;
        this.accountResolver = accountResolver;
        this.iamService = iamService;
        this.evaluator = evaluator;
        this.actionRegistry = actionRegistry;
        this.arnBuilder = arnBuilder;
        this.requestContext = requestContext;
        this.conditionContextResolver = conditionContextResolver;
        this.cloudTrailService = cloudTrailService;
        this.currentVertxRequest = currentVertxRequest;
        this.catalog = catalog;
        this.scpProvider = scpProvider;
        this.organizationProvider = organizationProvider;
        this.sessionAccountLookup = sessionAccountLookup;
        this.resourcePolicyLookup = resourcePolicyLookup;
    }

    @Override
    public void filter(ContainerRequestContext ctx) {
        if (!config.services().iam().enforcementEnabled()) {
            return;
        }

        String auth = ctx.getHeaderString("Authorization");
        if (auth == null) {
            auth = presignedCredentialAsAuthorization(ctx);
        }
        if (auth == null) {
            return;
        }

        String akid = accountResolver.extractAccessKeyId(auth);
        if (akid == null) {
            return; // not an AWS SigV4 credential: a Bearer or Basic scheme decided by its route
        }

        String rawScope = extractCredentialScope(auth);
        if (rawScope == null) {
            return;
        }
        // Normalise signing aliases (s3express → s3) before anything keyed by scope runs:
        // action rules, ARN building and condition keys all match the canonical name, so an
        // alias would resolve to no action and be allowed through without any policy check.
        String credentialScope = catalog.canonicalCredentialScope(rawScope);

        String action = actionRegistry.resolve(credentialScope, ctx);
        if (action == null) {
            // An action this emulator cannot name is an action no policy can allow. Enforcement
            // that allowed it would grant, by omission, exactly the calls nobody wrote a rule for.
            LOG.infov("IAM enforcement DENY: akid={0} unmapped action for {1} {2} {3}",
                    akid, credentialScope, ctx.getMethod(), ctx.getUriInfo().getPath());
            ctx.abortWith(unmappedActionResponse(credentialScope, ctx.getMediaType()));
            return;
        }
        if ("sts:GetCallerIdentity".equals(action)) {
            return; // AWS returns caller identity even when an identity policy explicitly denies it
        }

        String region = requestContext.getRegion() == null ? config.defaultRegion() : requestContext.getRegion();
        String accountId = requestContext.getAccountId() == null
                ? accountResolver.resolve(auth)
                : requestContext.getAccountId();

        // Service control policies from the caller's organization, when the Organizations
        // service is present and SCP enforcement is enabled. Resolved lazily via Instance
        // to avoid a hard IAM → Organizations dependency.
        //
        // Resolved before resolveCallerContext because the account-root branch below needs to
        // know whether a ceiling exists in order to decide between enforcing and bypassing. That
        // costs an organization lookup on requests that then bypass; both flags are opt-in, and
        // effectiveScpLevels returns null immediately when SCP enforcement is off.
        List<List<String>> scpLevels = scpProvider.isResolvable()
                ? scpProvider.get().effectiveScpLevels(accountId)
                : null;

        boolean accountRootPrincipal = false;
        CallerContext caller = iamService.resolveCallerContext(akid);
        if (caller == null) {
            // A bare 12-digit account-id key is floci's account-root principal: not a registered
            // IAM identity (resolveCallerContext → null), but a real principal all the same, with
            // full access bounded by SCPs.
            if (akid.equals(accountId)) {
                caller = CallerContext.of(List.of(ROOT_ALLOW_ALL));
                accountRootPrincipal = true;
            } else {
                // Every other empty context is a caller enforcement cannot evaluate: an access key
                // this account never issued, a session that has expired, or an identity session
                // carrying no role. Under enforcement each one is refused, never allowed.
                LOG.infov("IAM enforcement DENY: akid={0} is not a principal of account {1}",
                        akid, accountId);
                ctx.abortWith(accessDeniedResponse(action, credentialScope, ctx.getMediaType()));
                return;
            }
        }
        if (scpLevels != null) {
            caller = caller.withScpLevels(scpLevels);
        }

        List<String> resources = arnBuilder.buildResources(credentialScope, ctx, region, accountId);

        Map<String, List<String>> conditionContext = conditionContextResolver.resolve(credentialScope, action, ctx);
        // A request naming several resources is authorized once per resource, as on AWS, so a
        // permitted first target cannot carry later targets that the policy does not allow.
        List<Map<String, List<String>>> remainingTargets =
                conditionContextResolver.resolveRemainingTargets(credentialScope, action, ctx);

        // aws:PrincipalArn is populated for every principal this filter can identify — IAM users,
        // assumed-role sessions, and now the synthesized account-root principal above, using AWS's
        // own root ARN shape (arn:aws:iam::<account>:root). Real AWS populates this key for the
        // root user, so a DenyRootUser guardrail keyed on it must fire against floci's account-root
        // stand-in the same way it enforces SCPs against it (the account-root SCP change above);
        // leaving it absent here would have made the two forms of root enforcement inconsistent.
        RequestPrincipal principal = accountRootPrincipal
                ? RequestPrincipal.accountRoot(accountId)
                : iamService.resolveCallerPrincipal(akid).orElse(null);
        caller = caller.withPrincipal(principal);
        // The principal keys describe the caller and so are the same for every resource the
        // request names: aws:PrincipalArn, and aws:PrincipalAccount with the organization keys
        // aws:PrincipalOrgID and aws:PrincipalOrgPaths. They are set here rather than in
        // IamConditionContextResolver because that resolver answers per service and these apply
        // to every request, whatever the service.
        Map<String, List<String>> principalKeys = principalConditionKeys(akid, principal, accountId);
        List<Map<String, List<String>>> targetContexts = new ArrayList<>();
        targetContexts.add(withKeys(conditionContext, principalKeys));
        for (Map<String, List<String>> target : remainingTargets) {
            targetContexts.add(withKeys(target, principalKeys));
        }

        for (String resource : resources) {
            ResourcePolicies resourcePolicies = resourcePolicyLookup.policiesFor(resource);
            // One request may name several resources, each owned by its own account, so the
            // resource keys and the resource's own organization ceiling are resolved per resource.
            String resourceAccountId = resourceAccountOf(resourcePolicies, resource);
            Map<String, List<String>> resourceKeys = resourceConditionKeys(resourceAccountId);
            List<List<String>> rcpLevels =
                    resourceControlPolicyLevels(credentialScope, resourceAccountId, principal);
            for (Map<String, List<String>> targetContext : targetContexts) {
                Decision decision = evaluator.evaluate(caller, resourcePolicies, rcpLevels, action,
                        resource, withKeys(targetContext, resourceKeys));
                if (decision != Decision.DENY) {
                    continue;
                }
                LOG.infov("IAM enforcement DENY: akid={0} action={1} resource={2}", akid, action, resource);
                String denyMessage = "User: arn:aws:iam::" + accountId
                        + ":user/" + akid + " is not authorized to perform: " + action
                        + " on resource: \"" + resource + "\""
                        + " because no identity-based policy allows the " + action + " action";
                emitS3DenialIfApplicable(akid, action, resource, ctx, region, denyMessage);
                ctx.abortWith(accessDeniedResponse(action, credentialScope, ctx.getMediaType()));
                return;
            }
        }
    }

    /**
     * Authorizes a single (action, resource) pair for the caller identified by an
     * Authorization header, following the same identity resolution and bypass rules
     * as {@link #filter}. Callers use this for a secondary resource that never appears
     * in the request URL and so is invisible to {@link ResourceArnBuilder} - such as
     * the CopyObject/UploadPartCopy source object, which arrives only in the
     * {@code x-amz-copy-source} header.
     *
     * <p>Returns normally when the action is allowed, or when enforcement does not
     * apply to this request (enforcement disabled, no Authorization header, root or
     * unknown access key). Throws {@link AwsException} with the same AccessDenied
     * shape as {@link #filter} when the caller's policies deny the action.
     *
     * <p>The account used for policy evaluation is always re-resolved from {@code akid} here
     * (see {@link #resolveCredentialAccountId}) rather than trusted from {@link RequestContext},
     * because a presigned POST's credential is invisible to {@code AccountContextFilter} - it
     * arrives only in the multipart body, parsed well after that filter already set the ambient
     * account to the configured default. The resolved account is pushed onto {@link RequestContext}
     * for the duration of this call so that {@link IamService#resolveCallerContext} and
     * {@link IamService#resolveCallerArn}, which both key their per-account lookups off the
     * ambient account, resolve the credential's actual owner instead of the default account.
     */
    public void authorizeAdditionalResource(String authorizationHeader, String action, String resource) {
        if (!config.services().iam().enforcementEnabled()) {
            return;
        }
        if (authorizationHeader == null) {
            return;
        }
        String akid = accountResolver.extractAccessKeyId(authorizationHeader);
        if (akid == null) {
            return;
        }
        if (extractCredentialScope(authorizationHeader) == null) {
            return;
        }

        String accountId = resolveCredentialAccountId(akid, authorizationHeader);
        String previousAccountId = requestContext.getAccountId();
        requestContext.setAccountId(accountId);
        try {
            List<List<String>> scpLevels = scpProvider.isResolvable()
                    ? scpProvider.get().effectiveScpLevels(accountId) : null;

            boolean accountRootPrincipal = false;
            CallerContext caller = iamService.resolveCallerContext(akid);
            if (caller == null) {
                if (akid.equals(accountId)) {
                    caller = CallerContext.of(List.of(ROOT_ALLOW_ALL));
                    accountRootPrincipal = true;
                } else {
                    // Same refusal as filter(): an unknown key, an expired session, or a session
                    // with no role is a caller enforcement cannot evaluate, so it is refused.
                    LOG.infov("IAM enforcement DENY: akid={0} is not a principal of account {1}",
                            akid, accountId);
                    throw new AwsException("AccessDenied",
                            "User: " + akid + " is not authorized to perform: " + action
                                    + " because the credential is not a principal of account " + accountId,
                            403);
                }
            }
            if (scpLevels != null) {
                caller = caller.withScpLevels(scpLevels);
            }

            RequestPrincipal principal = accountRootPrincipal
                    ? RequestPrincipal.accountRoot(accountId)
                    : iamService.resolveCallerPrincipal(akid).orElse(null);
            caller = caller.withPrincipal(principal);

            ResourcePolicies resourcePolicies = resourcePolicyLookup.policiesFor(resource);
            String resourceAccountId = resourceAccountOf(resourcePolicies, resource);
            Map<String, List<String>> conditionContext = withKeys(
                    principalConditionKeys(akid, principal, accountId),
                    resourceConditionKeys(resourceAccountId));
            List<List<String>> rcpLevels =
                    resourceControlPolicyLevels(serviceOf(action), resourceAccountId, principal);
            Decision decision = evaluator.evaluate(caller, resourcePolicies, rcpLevels, action,
                    resource, conditionContext);
            if (decision != Decision.DENY) {
                return;
            }
            LOG.infov("IAM enforcement DENY: akid={0} action={1} resource={2}", akid, action, resource);
            throw new AwsException("AccessDenied",
                    "User: arn:aws:iam::" + accountId + ":user/" + akid
                            + " is not authorized to perform: " + action
                            + " on resource: \"" + resource + "\""
                            + " because no identity-based policy allows the " + action + " action",
                    403);
        } finally {
            requestContext.setAccountId(previousAccountId);
        }
    }

    /**
     * The condition keys that describe the caller: its ARN, its account, whether it is an AWS
     * service, its session tags, and, when that account belongs to an organization, that
     * organization's id and the account's organization path. An account in no organization carries
     * none of the organization keys, exactly as on AWS.
     *
     * <p>{@code aws:SourceOrgID} and {@code aws:SourceOrgPaths} are deliberately absent. AWS sets
     * them only where a service calls on behalf of a resource that belongs to an organization, and
     * they describe that source resource's organization, not the caller's. Nothing in this
     * emulator makes such a call, so writing a value here would be inventing one: a policy reading
     * them behaves as it does on AWS for a call no service made, which is the case at hand.
     */
    private Map<String, List<String>> principalConditionKeys(String akid, RequestPrincipal principal,
                                                             String accountId) {
        Map<String, List<String>> keys = new HashMap<>();
        if (principal != null && principal.arn() != null) {
            keys.put("aws:PrincipalArn", List.of(principal.arn()));
        }
        // Present on every request, false for anything that signs with a credential, which is
        // everything that reaches this filter.
        keys.put("aws:PrincipalIsAWSService",
                List.of(Boolean.toString(principal != null && principal.service() != null)));
        iamService.sessionTags(akid)
                .forEach((tag, value) -> keys.put("aws:PrincipalTag/" + tag, List.of(value)));
        String principalAccount = principal != null && principal.accountId() != null
                ? principal.accountId() : accountId;
        if (principalAccount != null) {
            keys.put("aws:PrincipalAccount", List.of(principalAccount));
            organizationOf(principalAccount).ifPresent(organization -> {
                keys.put("aws:PrincipalOrgID", List.of(organization.organizationId()));
                keys.put("aws:PrincipalOrgPaths", List.of(organization.path()));
            });
        }
        return keys;
    }

    /** The same three facts about the account that owns the resource the request names. */
    private Map<String, List<String>> resourceConditionKeys(String resourceAccountId) {
        if (resourceAccountId == null) {
            return Map.of();
        }
        Map<String, List<String>> keys = new HashMap<>();
        keys.put("aws:ResourceAccount", List.of(resourceAccountId));
        organizationOf(resourceAccountId).ifPresent(organization -> {
            keys.put("aws:ResourceOrgID", List.of(organization.organizationId()));
            keys.put("aws:ResourceOrgPaths", List.of(organization.path()));
        });
        return keys;
    }

    /**
     * The account that owns the resource: the owner the resource policy lookup already finds,
     * which is the only source for an S3 ARN because an S3 ARN carries no account, falling back to
     * the account the ARN itself names. Null when neither says, which leaves the resource keys
     * absent rather than claiming an account nothing established.
     */
    private String resourceAccountOf(ResourcePolicies resourcePolicies, String resource) {
        if (resourcePolicies != null && resourcePolicies.ownerAccountId() != null) {
            return resourcePolicies.ownerAccountId();
        }
        if (resource == null || !AwsArnUtils.isArn(resource)) {
            return null;
        }
        String account = AwsArnUtils.accountOrDefault(resource, null);
        return account == null || account.isBlank() ? null : account;
    }

    /**
     * The resource control policies bounding the account that owns the resource, or null when
     * none apply: the service is not one AWS supports resource control policies for, the owner is
     * unknown, or the caller is a service-linked role, which AWS exempts.
     */
    private List<List<String>> resourceControlPolicyLevels(String credentialScope,
                                                           String resourceAccountId,
                                                           RequestPrincipal principal) {
        if (resourceAccountId == null
                || !RESOURCE_CONTROL_POLICY_SCOPES.contains(credentialScope)
                || isServiceLinkedRole(principal)
                || !organizationProvider.isResolvable()) {
            return null;
        }
        return organizationProvider.get().effectiveRcpLevels(resourceAccountId);
    }

    /** The credential scope an action names, {@code s3} for {@code s3:GetObject}. */
    private static String serviceOf(String action) {
        if (action == null) {
            return null;
        }
        int colon = action.indexOf(':');
        return colon <= 0 ? null : action.substring(0, colon);
    }

    private static boolean isServiceLinkedRole(RequestPrincipal principal) {
        if (principal == null) {
            return false;
        }
        return (principal.roleArn() != null && principal.roleArn().contains(SERVICE_LINKED_ROLE_PATH))
                || (principal.arn() != null && principal.arn().contains(SERVICE_LINKED_ROLE_PATH));
    }

    private Optional<AccountOrganization> organizationOf(String accountId) {
        return organizationProvider.isResolvable()
                ? organizationProvider.get().organizationOf(accountId)
                : Optional.empty();
    }

    /**
     * A copy of {@code context} with {@code keys} added. The contexts a resolver returns are read
     * once per resource, so each resource's keys go onto a copy rather than onto the shared map.
     */
    private static Map<String, List<String>> withKeys(Map<String, List<String>> context,
                                                      Map<String, List<String>> keys) {
        if (keys.isEmpty()) {
            return context;
        }
        Map<String, List<String>> merged = context == null ? new HashMap<>() : new HashMap<>(context);
        merged.putAll(keys);
        return merged;
    }

    /**
     * Resolves the account that owns {@code akid} directly from the credential, following the
     * same precedence {@link AccountContextFilter} applies to a header or presigned-URL request:
     * a 12-digit access key ID is the account itself, otherwise {@link SessionAccountLookup}
     * looks up the owning account for an IAM or session credential, falling back to the configured
     * default account when neither resolves.
     */
    private String resolveCredentialAccountId(String akid, String authorizationHeader) {
        if (akid != null && !akid.matches("\\d{12}")) {
            Optional<String> credentialAccount = sessionAccountLookup.resolveAccountId(akid);
            if (credentialAccount.isPresent()) {
                return credentialAccount.get();
            }
        }
        return accountResolver.resolve(authorizationHeader);
    }

    /**
     * Best-effort CloudTrail emission for S3 access denials. Without this hook,
     * denied requests get aborted before {@code S3Controller}'s try/catch sees
     * them, so denials would never appear in CloudTrail logs — leaving a major
     * gap vs. real AWS for downstream audit ingestion. Failures here never
     * propagate (the deny response is the load-bearing behavior).
     */
    private void emitS3DenialIfApplicable(String akid, String action, String resource,
                                          ContainerRequestContext ctx, String region,
                                          String denyMessage) {
        try {
            if (action == null || !action.startsWith("s3:")) {
                return;
            }
            String eventName = mapS3ActionToEventName(action, ctx.getMethod());
            if (eventName == null) {
                return;
            }
            String[] bk = parseS3Resource(resource);
            String bucket = bk[0];
            String key = bk[1];

            String userAgent = null;
            String sourceIp = null;
            try {
                var rc = currentVertxRequest.getCurrent();
                if (rc != null) {
                    var req = rc.request();
                    if (req != null) {
                        userAgent = req.getHeader("User-Agent");
                        String fwd = req.getHeader("X-Forwarded-For");
                        if (fwd != null && !fwd.isBlank()) {
                            int comma = fwd.indexOf(',');
                            sourceIp = (comma > 0 ? fwd.substring(0, comma) : fwd).trim();
                        } else if (req.remoteAddress() != null) {
                            sourceIp = req.remoteAddress().host();
                        }
                    }
                }
            } catch (Exception e) {
                LOG.tracev(e, "CloudTrail: could not extract request context for IAM denial {0} on {1}", action, resource);
            }

            cloudTrailService.emitS3DataEvent(CloudTrailService.S3EventInput.builder()
                    .region(region)
                    .eventName(eventName)
                    .bucketName(bucket)
                    .key(key)
                    .accessKeyId(akid)
                    .sourceIp(sourceIp)
                    .userAgent(userAgent)
                    .errorCode("AccessDenied")
                    .errorMessage(denyMessage)
                    .eventTimeMillis(System.currentTimeMillis())
                    .build());
        } catch (RuntimeException e) {
            LOG.tracev(e, "CloudTrail denial emission failed for {0} on {1}", action, resource);
        }
    }

    // Package-private for unit testing.
    static String mapS3ActionToEventName(String action, String httpMethod) {
        if (action == null) return null;
        // Action set sourced from IamActionRegistry — see that file for any
        // additions. HEAD on an object is bucketed under s3:GetObject by the
        // registry, so we distinguish via httpMethod.
        return switch (action) {
            case "s3:GetObject" -> "HEAD".equalsIgnoreCase(httpMethod) ? "HeadObject" : "GetObject";
            case "s3:PutObject" -> "PutObject";
            case "s3:DeleteObject" -> "DeleteObject";
            case "s3:ListBucket" -> "ListObjects";
            case "s3:ListAllMyBuckets" -> "ListBuckets";
            case "s3:GetObjectAcl" -> "GetObjectAcl";
            case "s3:PutObjectAcl" -> "PutObjectAcl";
            case "s3:GetObjectTagging" -> "GetObjectTagging";
            case "s3:PutObjectTagging" -> "PutObjectTagging";
            case "s3:DeleteObjectTagging" -> "DeleteObjectTagging";
            default -> null;
        };
    }

    /** Returns [bucket, key] (key may be null if the resource is a bucket-level ARN). */
    // Package-private for unit testing.
    static String[] parseS3Resource(String resource) {
        if (resource == null || !resource.startsWith("arn:aws:s3:::")) {
            return new String[] { null, null };
        }
        String tail = resource.substring("arn:aws:s3:::".length());
        if (tail.isEmpty() || "*".equals(tail)) {
            return new String[] { null, null };
        }
        int slash = tail.indexOf('/');
        if (slash < 0) {
            return new String[] { tail, null };
        }
        String bucket = tail.substring(0, slash);
        String key = tail.substring(slash + 1);
        return new String[] { bucket, key.isEmpty() ? null : key };
    }

    private String extractCredentialScope(String auth) {
        Matcher m = SERVICE_PATTERN.matcher(auth);
        return m.find() ? m.group(1) : null;
    }

    /**
     * Presigned URLs (and presigned POST forms, handled separately via
     * {@link #authorizeAdditionalResource}) sign via the {@code X-Amz-Credential} query
     * parameter instead of the {@code Authorization} header, so {@code ctx.getHeaderString}
     * alone misses them and this filter would silently skip IAM identity-policy evaluation for
     * every presigned request. {@link AccountContextFilter} already resolves account/region the
     * same way for the same reason. Synthesizing a {@code Credential=...} string from the query
     * parameter lets every downstream step here - access key extraction, credential scope,
     * action resolution, resource ARNs - run unchanged for both signing styles.
     */
    private static String presignedCredentialAsAuthorization(ContainerRequestContext ctx) {
        String credential = ctx.getUriInfo().getQueryParameters().getFirst("X-Amz-Credential");
        return credential == null || credential.isBlank() ? null : "Credential=" + credential;
    }

    /**
     * Builds a 403 Access Denied response in the wire format the calling SDK
     * expects. AWS SDKs hard-fail when they receive the wrong shape: an XML
     * parser blows up on a leading {@code {}, and a JSON parser blows up on
     * {@code <}. Pick the shape from request signals:
     *
     * <ul>
     *   <li>S3 → S3-flavored XML {@code <Error>...</Error>}</li>
     *   <li>{@code application/x-www-form-urlencoded} body → AWS Query
     *       {@code <ErrorResponse>...</ErrorResponse>} (IAM/STS/EC2/SQS/SNS/...)</li>
     *   <li>everything else (JSON 1.x, REST-JSON) → keep the historical JSON shape</li>
     * </ul>
     */
    // Package-private for unit testing.
    static Response accessDeniedResponse(String action, String credentialScope, MediaType requestMediaType) {
        String message = "User is not authorized to perform: " + action;
        if ("s3".equals(credentialScope)) {
            return s3XmlAccessDenied(message);
        }
        if (isFormEncoded(requestMediaType)) {
            return queryXmlAccessDenied(message);
        }
        return jsonAccessDenied(message);
    }

    /**
     * The refusal for a request whose action {@link IamActionRegistry} cannot name. It is an
     * AccessDenied in the same shape as any other, naming the service the credential was scoped to,
     * because that is all that is known: without an action there is nothing to write a policy about.
     */
    // Package-private for unit testing.
    static Response unmappedActionResponse(String credentialScope, MediaType requestMediaType) {
        return accessDeniedResponse(credentialScope + ":*", credentialScope, requestMediaType);
    }

    private static boolean isFormEncoded(MediaType mt) {
        return mt != null
                && "application".equalsIgnoreCase(mt.getType())
                && "x-www-form-urlencoded".equalsIgnoreCase(mt.getSubtype());
    }

    private static Response queryXmlAccessDenied(String message) {
        String xml = new XmlBuilder()
                .start("ErrorResponse")
                  .start("Error")
                    .elem("Type", "Sender")
                    .elem("Code", "AccessDenied")
                    .elem("Message", message)
                  .end("Error")
                  .elem("RequestId", UUID.randomUUID().toString())
                .end("ErrorResponse")
                .build();
        return Response.status(403).type(MediaType.APPLICATION_XML).entity(xml).build();
    }

    private static Response s3XmlAccessDenied(String message) {
        String xml = new XmlBuilder()
                .raw("<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
                .start("Error")
                  .elem("Code", "AccessDenied")
                  .elem("Message", message)
                  .elem("RequestId", UUID.randomUUID().toString())
                .end("Error")
                .build();
        return Response.status(403).type(MediaType.APPLICATION_XML).entity(xml).build();
    }

    private static Response jsonAccessDenied(String message) {
        String body = "{\"__type\":\"AccessDeniedException\",\"message\":\"" + message + "\"}";
        return Response.status(403).type(MediaType.APPLICATION_JSON).entity(body).build();
    }
}

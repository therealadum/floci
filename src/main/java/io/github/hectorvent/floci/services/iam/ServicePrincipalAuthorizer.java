package io.github.hectorvent.floci.services.iam;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.services.iam.IamPolicyEvaluator.Decision;
import io.github.hectorvent.floci.services.iam.model.CallerContext;
import io.github.hectorvent.floci.services.iam.model.RequestPrincipal;
import io.github.hectorvent.floci.services.iam.model.ResourcePolicies;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.util.List;
import java.util.Map;

/**
 * Whether an AWS service, acting on its own behalf inside the emulator, may take an action on a
 * resource.
 *
 * <p>{@code IamEnforcementFilter} authorizes what arrives over HTTP with a signature. A service
 * that delivers in process — EventBridge publishing to an SNS target — carries no credential and
 * never reaches that filter, so without this it is authorized by nothing at all. A service
 * principal has no identity policy anywhere; on AWS its access is exactly what the resource's own
 * policy grants it, which is why a rule with an SNS target needs a topic policy naming
 * {@code events.amazonaws.com}.</p>
 *
 * <p>The request carries {@code aws:PrincipalIsAWSService} true and
 * {@code aws:PrincipalServiceName}, as AWS sets them for such a call. It carries no
 * {@code aws:SourceArn} or {@code aws:SourceAccount}: those describe the resource a service acts
 * on behalf of, and writing one here would be inventing a value, exactly as
 * {@code IamEnforcementFilter} declines to invent {@code aws:SourceOrgID}.</p>
 *
 * <p>Like every other enforcement, this answers true whenever IAM enforcement is off, so the
 * emulator's default remains that nothing is refused.</p>
 */
@ApplicationScoped
public class ServicePrincipalAuthorizer {

    private static final Logger LOG = Logger.getLogger(ServicePrincipalAuthorizer.class);

    private final EmulatorConfig config;
    private final ResourcePolicyLookup resourcePolicyLookup;
    private final IamPolicyEvaluator evaluator;

    @Inject
    public ServicePrincipalAuthorizer(EmulatorConfig config,
                                      ResourcePolicyLookup resourcePolicyLookup,
                                      IamPolicyEvaluator evaluator) {
        this.config = config;
        this.resourcePolicyLookup = resourcePolicyLookup;
        this.evaluator = evaluator;
    }

    /**
     * @param servicePrincipal the service acting, as {@code <service>.amazonaws.com}
     * @param action           the IAM action, as {@code sns:Publish}
     * @param resourceArn      the resource the action targets
     * @return whether the resource's own policy allows that service that action
     */
    public boolean allows(String servicePrincipal, String action, String resourceArn) {
        if (!config.services().iam().enforcementEnabled()) {
            return true;
        }
        ResourcePolicies policies = resourcePolicyLookup.policiesFor(resourceArn);
        CallerContext caller = CallerContext.of(List.of())
                .withPrincipal(RequestPrincipal.service(null, servicePrincipal));
        Map<String, List<String>> conditionContext = Map.of(
                "aws:PrincipalIsAWSService", List.of("true"),
                "aws:PrincipalServiceName", List.of(servicePrincipal));
        Decision decision =
                evaluator.evaluate(caller, policies, null, action, resourceArn, conditionContext);
        if (decision == Decision.DENY) {
            LOG.infov("IAM enforcement DENY: service={0} action={1} resource={2}",
                    servicePrincipal, action, resourceArn);
            return false;
        }
        return true;
    }
}

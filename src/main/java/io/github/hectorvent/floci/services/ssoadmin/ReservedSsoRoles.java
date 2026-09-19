package io.github.hectorvent.floci.services.ssoadmin;

import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.iam.model.IamRole;
import io.github.hectorvent.floci.services.ssoadmin.model.PermissionSet;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.time.Duration;
import java.util.List;

/**
 * The IAM role IAM Identity Center provisions into a target account for a permission set.
 *
 * <p>On AWS an account assignment does two things: it records the assignment, and it provisions a
 * role into the target account named {@code AWSReservedSSO_<PermissionSetName>_<suffix>} under the
 * path {@code /aws-reserved/sso.amazonaws.com/}, carrying the permission set's managed and inline
 * policies and trusted for SAML federation through the account's Identity Center SAML provider.
 * That role is what a person's console session and a deploy from the administrator permission set
 * actually run as, so its ARN is a thing other trust policies name.
 *
 * <p>The suffix is AWS's per-account, per-permission-set discriminator and is stable for the life
 * of the provisioning; the emulator uses one fixed suffix, {@value #SUFFIX}, which
 * {@code SsoPortalService} already mints into the ARN it hands a portal session, so the role the
 * portal names and the role in the account's IAM are the same role.
 */
@ApplicationScoped
public class ReservedSsoRoles {

    /** The path AWS reserves for the roles IAM Identity Center owns in a member account. */
    public static final String PATH = IamService.RESERVED_SSO_ROLE_PATH;

    /** The emulator's stand-in for AWS's random per-provisioning suffix. */
    public static final String SUFFIX = "floci";

    /** The SAML provider IAM Identity Center creates in every account it provisions a role into. */
    private static final String SAML_PROVIDER = "AWSSSO_" + SUFFIX + "_DO_NOT_DELETE";

    private static final String TRUST_POLICY = """
            {"Version":"2012-10-17","Statement":[{"Effect":"Allow",\
            "Principal":{"Federated":"arn:aws:iam::%s:saml-provider/%s"},\
            "Action":["sts:AssumeRoleWithSAML","sts:TagSession"],\
            "Condition":{"StringEquals":{"SAML:aud":"https://signin.aws.amazon.com/saml"}}}]}""";

    private static final int DEFAULT_SESSION_SECONDS = 3600;

    private final IamService iamService;

    @Inject
    public ReservedSsoRoles(IamService iamService) {
        this.iamService = iamService;
    }

    /** The role name AWS gives the permission set's role in every account it is provisioned to. */
    public static String roleName(String permissionSetName) {
        return "AWSReservedSSO_" + permissionSetName + "_" + SUFFIX;
    }

    /**
     * Creates the role if the permission set has none in the account, and in either case brings
     * its session duration and its policies up to the permission set's current shape. This is the
     * provisioning half of {@code CreateAccountAssignment} and of {@code ProvisionPermissionSet}.
     */
    public void provision(String accountId, PermissionSet permissionSet) {
        String name = roleName(permissionSet.name());
        int sessionSeconds = sessionSeconds(permissionSet);
        IamRole role = iamService.findRole(accountId, name).orElseGet(() ->
                iamService.createRoleForAccount(accountId, name, PATH,
                        TRUST_POLICY.formatted(accountId, SAML_PROVIDER),
                        "Provisioned by IAM Identity Center for permission set " + permissionSet.name() + ".",
                        sessionSeconds, null));
        role.setMaxSessionDuration(sessionSeconds);
        role.setAttachedPolicyArns(List.copyOf(permissionSet.managedPolicies().keySet()));
        role.getInlinePolicies().clear();
        if (permissionSet.inlinePolicy() != null && !permissionSet.inlinePolicy().isBlank()) {
            role.getInlinePolicies().put(permissionSet.name(), permissionSet.inlinePolicy());
        }
        iamService.saveRoleForAccount(accountId, role);
    }

    /**
     * Removes the role, which AWS does when the last assignment of that permission set to that
     * account goes, and when the permission set itself is deleted.
     */
    public void remove(String accountId, String permissionSetName) {
        iamService.deleteRoleForAccount(accountId, roleName(permissionSetName));
    }

    private static int sessionSeconds(PermissionSet permissionSet) {
        if (permissionSet.sessionDuration() == null || permissionSet.sessionDuration().isBlank()) {
            return DEFAULT_SESSION_SECONDS;
        }
        return (int) Duration.parse(permissionSet.sessionDuration()).toSeconds();
    }
}

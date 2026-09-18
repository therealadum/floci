package io.github.hectorvent.floci.services.iam;

import io.github.hectorvent.floci.services.iam.model.AccountOrganization;

import java.util.List;
import java.util.Optional;

/**
 * Supplies what IAM needs to know about an account's place in an organization: the facts behind
 * the organization condition keys, and the resource control policies that bound what may be done
 * to that account's resources.
 *
 * <p>Implemented by the Organizations service and consumed lazily through
 * {@code Instance<OrganizationProvider>}, the same direction {@link ScpProvider} runs in: IAM
 * never depends on Organizations, and the emulator still works with Organizations disabled.</p>
 */
public interface OrganizationProvider {

    /**
     * @return where {@code accountId} sits in its organization, or empty when the account is in
     *         none — which is how an account outside any organization carries none of the
     *         organization condition keys, as on AWS. The management account carries them.
     */
    Optional<AccountOrganization> organizationOf(String accountId);

    /**
     * The effective resource control policies for the account that <em>owns</em> a resource, one
     * list of policy documents per organization level (root, each OU on the path, then the
     * account). They bound what any principal may do to that account's resources, its own
     * principals and outside ones alike, and they never grant.
     *
     * @return {@code null} when resource control policies don't apply: organization policy
     *         enforcement is disabled, the owning account is not in an organization, the owning
     *         account is the organization's management account (exempt on AWS), or the
     *         {@code RESOURCE_CONTROL_POLICY} type is not enabled on the root.
     */
    List<List<String>> effectiveRcpLevels(String resourceAccountId);
}

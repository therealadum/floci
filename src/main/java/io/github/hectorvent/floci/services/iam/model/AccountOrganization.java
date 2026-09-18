package io.github.hectorvent.floci.services.iam.model;

/**
 * Where one account sits in an organization: the facts behind the organization condition keys.
 *
 * <ul>
 *   <li>{@code organizationId} — {@code o-<org>}, the value of {@code aws:PrincipalOrgID} and
 *       {@code aws:ResourceOrgID}.</li>
 *   <li>{@code path} — AWS's organization path form,
 *       {@code o-<org>/r-<root>/ou-<ou>/.../<accountId>/}, trailing slash included. It is the
 *       single value of {@code aws:PrincipalOrgPaths} and {@code aws:ResourceOrgPaths}, both of
 *       which are multi-valued keys, and the same string the Organizations API reports as an
 *       OU's {@code Path} and as the one entry of an account's {@code Paths}.</li>
 *   <li>{@code managementAccount} — whether this is the organization's management account, which
 *       service control policies and resource control policies both exempt.</li>
 * </ul>
 */
public record AccountOrganization(String organizationId, String path, boolean managementAccount) {
}

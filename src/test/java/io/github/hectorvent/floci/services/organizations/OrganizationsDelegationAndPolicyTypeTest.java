package io.github.hectorvent.floci.services.organizations;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.storage.AccountAwareStorageBackend;
import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.organizations.model.Organization;
import io.github.hectorvent.floci.services.organizations.model.OrganizationPolicy;
import io.github.hectorvent.floci.services.organizations.model.OrganizationalUnit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

/**
 * Trusted service access and delegated administration, the guards on the resource control policy
 * type, and the organization lookup the enforcement filter makes on every request.
 */
class OrganizationsDelegationAndPolicyTypeTest {

    private static final String MANAGEMENT_ACCOUNT = "100000000001";
    private static final String SERVICE_PRINCIPAL = "cloudtrail.amazonaws.com";

    private OrganizationsService service;

    @BeforeEach
    void setUp() {
        service = new OrganizationsService(
                new ObjectMapper(),
                mock(IamService.class),
                AccountAwareStorageBackend.inMemory(MANAGEMENT_ACCOUNT),
                AccountAwareStorageBackend.inMemory(MANAGEMENT_ACCOUNT),
                AccountAwareStorageBackend.inMemory(MANAGEMENT_ACCOUNT),
                AccountAwareStorageBackend.inMemory(MANAGEMENT_ACCOUNT),
                AccountAwareStorageBackend.inMemory(MANAGEMENT_ACCOUNT),
                AccountAwareStorageBackend.inMemory(MANAGEMENT_ACCOUNT));
    }

    private Organization organization() {
        return service.createOrganization(MANAGEMENT_ACCOUNT, "ALL");
    }

    private String memberAccount(String name) {
        return service.createAccount(MANAGEMENT_ACCOUNT, name + "@floci.test", name, null, false)
                .getAccountId();
    }

    // ──────────────────────────── Trusted access and delegation ────────────────────────────

    @Test
    void aDelegatedAdministratorNeedsTrustedAccessForTheServiceFirst() {
        organization();
        String member = memberAccount("security");

        AwsException refusal = assertThrows(AwsException.class, () ->
                service.registerDelegatedAdministrator(MANAGEMENT_ACCOUNT, member, SERVICE_PRINCIPAL));
        assertEquals("ConstraintViolationException", refusal.getErrorCode());
        assertTrue(refusal.getMessage().contains("SERVICE_ACCESS_NOT_ENABLED"), refusal.getMessage());
        assertTrue(service.listDelegatedAdministrators(MANAGEMENT_ACCOUNT, SERVICE_PRINCIPAL).isEmpty());

        service.enableAWSServiceAccess(MANAGEMENT_ACCOUNT, SERVICE_PRINCIPAL);
        service.registerDelegatedAdministrator(MANAGEMENT_ACCOUNT, member, SERVICE_PRINCIPAL);

        assertEquals(List.of(member), service.listDelegatedAdministrators(MANAGEMENT_ACCOUNT, SERVICE_PRINCIPAL)
                .stream().map(account -> account.getId()).toList());
        assertEquals(List.of(SERVICE_PRINCIPAL),
                service.listDelegatedServicesForAccount(MANAGEMENT_ACCOUNT, member).stream()
                        .map(OrganizationsService.DelegatedService::servicePrincipal).toList());
        assertEquals(List.of(SERVICE_PRINCIPAL),
                service.listAWSServiceAccessForOrganization(MANAGEMENT_ACCOUNT).stream()
                        .map(OrganizationsService.EnabledServicePrincipal::servicePrincipal).toList());
    }

    @Test
    void trustedAccessStaysWhileADelegatedAdministratorIsRegistered() {
        organization();
        String member = memberAccount("security");
        service.enableAWSServiceAccess(MANAGEMENT_ACCOUNT, SERVICE_PRINCIPAL);
        service.registerDelegatedAdministrator(MANAGEMENT_ACCOUNT, member, SERVICE_PRINCIPAL);

        AwsException refusal = assertThrows(AwsException.class, () ->
                service.disableAWSServiceAccess(MANAGEMENT_ACCOUNT, SERVICE_PRINCIPAL));
        assertEquals("ConstraintViolationException", refusal.getErrorCode());

        service.deregisterDelegatedAdministrator(MANAGEMENT_ACCOUNT, member, SERVICE_PRINCIPAL);
        service.disableAWSServiceAccess(MANAGEMENT_ACCOUNT, SERVICE_PRINCIPAL);
        assertTrue(service.listAWSServiceAccessForOrganization(MANAGEMENT_ACCOUNT).isEmpty());
    }

    // ──────────────────────────── The resource control policy type ────────────────────────────

    @Test
    void theLastResourceControlPolicyOnATargetCannotBeDetached() {
        Organization organization = organization();
        service.enablePolicyType(MANAGEMENT_ACCOUNT, organization.getRoot().getId(),
                "RESOURCE_CONTROL_POLICY");
        String member = memberAccount("workload");

        AwsException refusal = assertThrows(AwsException.class, () -> service.detachPolicy(
                MANAGEMENT_ACCOUNT, OrganizationsService.RCP_FULL_AWS_ACCESS_POLICY_ID, member));
        assertEquals("ConstraintViolationException", refusal.getErrorCode());

        OrganizationPolicy second = service.createPolicy(MANAGEMENT_ACCOUNT,
                "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\","
                        + "\"Action\":\"s3:*\",\"Resource\":\"*\"}]}",
                null, "DenyBuckets", "RESOURCE_CONTROL_POLICY", null);
        service.attachPolicy(MANAGEMENT_ACCOUNT, second.getId(), member);
        service.detachPolicy(MANAGEMENT_ACCOUNT, OrganizationsService.RCP_FULL_AWS_ACCESS_POLICY_ID, member);

        assertEquals(List.of(second.getId()),
                service.listPoliciesForTarget(MANAGEMENT_ACCOUNT, member, "RESOURCE_CONTROL_POLICY")
                        .stream().map(OrganizationPolicy::getId).toList());
    }

    @Test
    void disablingTheResourceControlPolicyTypeRemovesRcpFullAwsAccessEverywhere() {
        Organization organization = organization();
        String rootId = organization.getRoot().getId();
        service.enablePolicyType(MANAGEMENT_ACCOUNT, rootId, "RESOURCE_CONTROL_POLICY");
        OrganizationalUnit unit = service.createOrganizationalUnit(MANAGEMENT_ACCOUNT, rootId, "Workloads", null);
        String member = memberAccount("workload");
        assertEquals(1, service.listPoliciesForTarget(MANAGEMENT_ACCOUNT, member,
                "RESOURCE_CONTROL_POLICY").size());

        service.disablePolicyType(MANAGEMENT_ACCOUNT, rootId, "RESOURCE_CONTROL_POLICY");

        assertTrue(service.listPolicies(MANAGEMENT_ACCOUNT, "RESOURCE_CONTROL_POLICY").isEmpty());
        for (String target : List.of(rootId, unit.getId(), member)) {
            assertTrue(service.listPoliciesForTarget(MANAGEMENT_ACCOUNT, target,
                    "RESOURCE_CONTROL_POLICY").isEmpty(), target);
        }
        assertThrows(AwsException.class, () -> service.describePolicy(
                MANAGEMENT_ACCOUNT, OrganizationsService.RCP_FULL_AWS_ACCESS_POLICY_ID));

        // Re-enabling puts it back on every target, as enabling it the first time did.
        service.enablePolicyType(MANAGEMENT_ACCOUNT, rootId, "RESOURCE_CONTROL_POLICY");
        for (String target : List.of(rootId, unit.getId(), member)) {
            assertEquals(List.of(OrganizationsService.RCP_FULL_AWS_ACCESS_POLICY_ID),
                    service.listPoliciesForTarget(MANAGEMENT_ACCOUNT, target, "RESOURCE_CONTROL_POLICY")
                            .stream().map(OrganizationPolicy::getId).toList(), target);
        }
    }

    // ──────────────────────────── The held organization lookup ────────────────────────────

    @Test
    void theHeldOrganizationLookupSeesEveryChangeToTheOrganization() {
        Organization organization = organization();
        String rootId = organization.getRoot().getId();

        assertTrue(service.organizationOf("100000000009").isEmpty());
        assertTrue(service.organizationOf(MANAGEMENT_ACCOUNT).orElseThrow().managementAccount());

        String member = memberAccount("workload");
        assertEquals(organization.getId() + "/" + rootId + "/" + member + "/",
                service.organizationOf(member).orElseThrow().path());

        OrganizationalUnit unit = service.createOrganizationalUnit(MANAGEMENT_ACCOUNT, rootId, "Workloads", null);
        service.moveAccount(MANAGEMENT_ACCOUNT, member, rootId, unit.getId());
        assertEquals(organization.getId() + "/" + rootId + "/" + unit.getId() + "/" + member + "/",
                service.organizationOf(member).orElseThrow().path());

        service.removeAccountFromOrganization(MANAGEMENT_ACCOUNT, member);
        assertEquals(Optional.empty(), service.organizationOf(member));
    }

    @Test
    void theHeldOrganizationLookupSeesAPolicyAttachedAfterItWasFirstRead() {
        Organization organization = organization();
        String rootId = organization.getRoot().getId();
        service.enablePolicyType(MANAGEMENT_ACCOUNT, rootId, "RESOURCE_CONTROL_POLICY");
        String member = memberAccount("workload");

        // Read once, so anything held is built before the policy exists.
        service.organizationOf(member);
        assertEquals(1, service.effectiveRcpLevels(member).get(1).size());

        OrganizationPolicy denial = service.createPolicy(MANAGEMENT_ACCOUNT,
                "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\","
                        + "\"Action\":\"s3:*\",\"Resource\":\"*\"}]}",
                null, "DenyBuckets", "RESOURCE_CONTROL_POLICY", null);
        service.attachPolicy(MANAGEMENT_ACCOUNT, denial.getId(), member);

        List<List<String>> levels = service.effectiveRcpLevels(member);
        assertEquals(2, levels.size());
        assertEquals(2, levels.get(1).size());
    }
}

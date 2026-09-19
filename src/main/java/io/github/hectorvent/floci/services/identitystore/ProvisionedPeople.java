package io.github.hectorvent.floci.services.identitystore;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.services.ssoadmin.SsoAdminService;
import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.util.List;

/**
 * The people the identity store holds from the start.
 *
 * <p>On AWS an identity store's people arrive over SCIM from Google Workspace, which is the one
 * thing a person connects by hand before the first deploy. The emulator has no Google, so the
 * addresses come from {@code floci.services.identitystore.provisioned-users} instead and each one
 * becomes a user at start. Nothing else creates them: a deploy that names a member the
 * configuration does not carry finds no user, which is the refusal the platform is checking for.
 */
@ApplicationScoped
public class ProvisionedPeople {

    private static final Logger LOG = Logger.getLogger(ProvisionedPeople.class);

    private final IdentityStoreService identityStoreService;
    private final SsoAdminService ssoAdminService;
    private final List<String> addresses;

    @Inject
    public ProvisionedPeople(IdentityStoreService identityStoreService,
                             SsoAdminService ssoAdminService,
                             EmulatorConfig config) {
        this.identityStoreService = identityStoreService;
        this.ssoAdminService = ssoAdminService;
        this.addresses = config.services().identitystore().provisionedUsers().orElse(List.of()).stream()
                .map(String::strip)
                .filter(address -> !address.isEmpty())
                .distinct()
                .toList();
    }

    void onStart(@Observes StartupEvent event) {
        provision();
    }

    /** Creates every configured person in the instance's identity store, idempotently. */
    public void provision() {
        if (addresses.isEmpty()) {
            return;
        }
        String storeId = ssoAdminService.getIdentityStoreId();
        for (String address : addresses) {
            identityStoreService.provisionUser(storeId, address);
        }
        LOG.infov("Provisioned {0} people into identity store {1}", addresses.size(), storeId);
    }

    /** The addresses the start configuration carries, in the order it carries them. */
    public List<String> addresses() {
        return addresses;
    }
}

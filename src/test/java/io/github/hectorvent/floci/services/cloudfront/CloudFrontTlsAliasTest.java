package io.github.hectorvent.floci.services.cloudfront;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.config.TlsCertificateManager;
import io.github.hectorvent.floci.core.storage.AccountAwareStorageBackend;
import io.github.hectorvent.floci.core.storage.StorageFactory;
import io.github.hectorvent.floci.services.cloudfront.model.Distribution;
import io.github.hectorvent.floci.services.cloudfront.model.DistributionConfig;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Floci's served certificate names {@code *.localhost.floci.io} one label deep, so an alias two
 * labels below the suffix is not covered until the distribution adds it, the way an API Gateway
 * custom domain does.
 */
class CloudFrontTlsAliasTest {

    private static final String ACCOUNT = "000000000000";
    private static final String ALIAS = "grafana.a.localhost.floci.io";

    /** One set of stores, so a second service over them is the same persistent volume after a restart. */
    private final Map<String, AccountAwareStorageBackend<?>> stores = new HashMap<>();

    private CloudFrontService service(TlsCertificateManager certificateManager) {
        StorageFactory storageFactory = Mockito.mock(StorageFactory.class);
        when(storageFactory.create(Mockito.anyString(), Mockito.anyString(), Mockito.any()))
                .thenAnswer(invocation -> stores.computeIfAbsent(
                        invocation.getArgument(1), k -> AccountAwareStorageBackend.inMemory(ACCOUNT)));

        EmulatorConfig config = Mockito.mock(EmulatorConfig.class);
        var servicesConfig = Mockito.mock(EmulatorConfig.ServicesConfig.class);
        var cloudFrontConfig = Mockito.mock(EmulatorConfig.CloudFrontServiceConfig.class);
        when(config.defaultAccountId()).thenReturn(ACCOUNT);
        when(config.services()).thenReturn(servicesConfig);
        when(servicesConfig.cloudfront()).thenReturn(cloudFrontConfig);
        when(cloudFrontConfig.domainSuffix()).thenReturn("localhost.floci.io");

        return new CloudFrontService(storageFactory, config, certificateManager);
    }

    private static Distribution distributionWithAliases(List<String> aliases) {
        DistributionConfig cfg = new DistributionConfig();
        cfg.setAliases(aliases);
        Distribution dist = new Distribution();
        dist.setConfig(cfg);
        return dist;
    }

    @Test
    void createDistributionAddsEveryAliasToTheServedCertificate() {
        TlsCertificateManager certificateManager = Mockito.mock(TlsCertificateManager.class);
        CloudFrontService service = service(certificateManager);

        service.createDistribution(distributionWithAliases(List.of(ALIAS)), Map.of());

        verify(certificateManager).ensureHost(ALIAS);
    }

    @Test
    void updateDistributionAddsEveryAliasToTheServedCertificate() {
        TlsCertificateManager certificateManager = Mockito.mock(TlsCertificateManager.class);
        CloudFrontService service = service(certificateManager);
        Distribution created = service.createDistribution(distributionWithAliases(List.of()), Map.of());

        service.updateDistribution(created.getId(), created.getEtag(),
                distributionWithAliases(List.of(ALIAS)));

        verify(certificateManager).ensureHost(ALIAS);
    }

    @Test
    void aDistributionWithNoAliasesTouchesTheServedCertificate() {
        TlsCertificateManager certificateManager = Mockito.mock(TlsCertificateManager.class);
        CloudFrontService service = service(certificateManager);

        Distribution created = service.createDistribution(new Distribution(), Map.of());
        service.updateDistribution(created.getId(), created.getEtag(), new Distribution());

        verifyNoInteractions(certificateManager);
    }

    @Test
    void startupAddsEveryAliasOfEveryPersistedDistribution() {
        service(Mockito.mock(TlsCertificateManager.class))
                .createDistribution(distributionWithAliases(List.of(ALIAS)), Map.of());

        TlsCertificateManager certificateManager = Mockito.mock(TlsCertificateManager.class);
        CloudFrontService restarted = service(certificateManager);
        restarted.onStart(null);

        verify(certificateManager).ensureHost(ALIAS);
    }
}

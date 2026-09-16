package io.github.hectorvent.floci.services.ecs;

import com.fasterxml.jackson.core.type.TypeReference;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.core.storage.AccountAwareStorageBackend;
import io.github.hectorvent.floci.core.storage.StorageFactory;
import io.github.hectorvent.floci.services.ecs.container.EcsContainerManager;
import io.github.hectorvent.floci.services.ecs.container.EcsTaskHandle;
import io.github.hectorvent.floci.services.ecs.model.Container;
import io.github.hectorvent.floci.services.ecs.model.ContainerDefinition;
import io.github.hectorvent.floci.services.ecs.model.EcsLoadBalancer;
import io.github.hectorvent.floci.services.ecs.model.EcsServiceModel;
import io.github.hectorvent.floci.services.ecs.model.EcsTask;
import io.github.hectorvent.floci.services.ecs.model.LaunchType;
import io.github.hectorvent.floci.services.ecs.model.NetworkBinding;
import io.github.hectorvent.floci.services.ecs.model.TaskStatus;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * A recreated Floci restores its ECS runtime at start: every persisted ACTIVE service launches its
 * tasks at once, without waiting for a request or for the five second tick, and the service is
 * named as pending until it has converged.
 */
class EcsRestorePersistedRuntimeTest {

    private static final String REGION = "us-east-1";
    private static final String ACCOUNT = "000000000000";

    @Test
    void restoreLaunchesTasksForAPersistedActiveServiceAndPendsItUntilConverged() {
        SharedStorageFactory storageFactory = new SharedStorageFactory();

        EcsService before = ecsService(storageFactory);
        before.initializeStorage();
        ContainerDefinition cd = new ContainerDefinition();
        cd.setName("app");
        cd.setImage("nginx:alpine");
        before.registerTaskDefinition("restore-fam", List.of(cd), null, null, null,
                null, null, List.of(), REGION);
        before.createCluster("restore-cluster", REGION);
        before.createService("restore-cluster", "restore-svc", "restore-fam", 1,
                LaunchType.FARGATE, List.of(), null, REGION);

        // The container is recreated on the same volume: a new process over the same state, with
        // the persisted service present and no task running.
        EcsService restored = ecsService(storageFactory);
        restored.initializeStorage();
        assertTrue(restored.listTasks("restore-cluster", null, null, "restore-svc", REGION).isEmpty(),
                "a recreated emulator starts with no task running");
        assertTrue(restored.pendingRestoredServices().isEmpty(),
                "nothing is pending before the restore");

        restored.restorePersistedRuntime();

        assertEquals(1,
                restored.listTasks("restore-cluster", null, null, "restore-svc", REGION).size(),
                "the restore launches the persisted service's task at once");
        Optional<Map<String, String>> pending = restored.pendingRestoredServices();
        assertTrue(pending.isPresent(), "the restored service is pending until it converges");
        assertTrue(pending.get().containsKey("restore-svc"),
                "the pending body names the service: " + pending.get());
        assertFalse(pending.get().get("restore-svc").isBlank(), "each pending service carries a reason");

        restored.reconcile();

        assertTrue(restored.pendingRestoredServices().isEmpty(),
                "once the service has converged nothing is pending");
    }

    @Test
    void aLoadBalancedServicePersistedAsCompletedStaysPendingUntilItsTaskRunsAgain() {
        // The service ran behind its load balancer before the restart, so its deployment is
        // persisted as completed. Its tasks are not persisted, so a recreated emulator holds a
        // service marked completed and an empty cell. reconcileService keeps such a deployment
        // completed, rightly; the restore gate must not read that mark, or health answers 200 on
        // a cell with no task in it, which is the failure this restore exists to prevent.
        SharedStorageFactory storageFactory = new SharedStorageFactory();
        EcsLoadBalancerRegistrar registrar = mock(EcsLoadBalancerRegistrar.class);
        when(registrar.pendingTargetReason(any(), any(), any())).thenReturn(Optional.empty());

        EcsService before = dockerModeEcsService(storageFactory, registrar);
        before.initializeStorage();
        before.createCluster("restore-cluster", REGION);
        registerTaskDefinition(before);
        before.createService("restore-cluster", "restore-svc", "restore-fam", 1,
                LaunchType.FARGATE, List.of(loadBalancer()), null, REGION);
        before.reconcileServices();
        before.reconcileServices();
        assertNotNull(persistedService(storageFactory).getLastCompletedDeploymentId(),
                "the persisted service must carry its deployment as completed");

        EcsService restored = dockerModeEcsService(storageFactory, registrar);
        restored.initializeStorage();
        restored.restorePersistedRuntime();

        assertEquals("tasks 0 of 1",
                restored.pendingRestoredServices().orElseThrow().get("restore-svc"),
                "a service persisted as completed is pending until a task runs again");

        restored.reconcileServices();

        assertTrue(restored.pendingRestoredServices().isEmpty(),
                "it leaves the pending set only once its task runs and its target is healthy");
    }

    private static EcsServiceModel persistedService(SharedStorageFactory storageFactory) {
        return storageFactory.servicesStore().scanAllAccountsWithRawKeys().values().iterator().next();
    }

    private static void registerTaskDefinition(EcsService service) {
        ContainerDefinition cd = new ContainerDefinition();
        cd.setName("app");
        cd.setImage("nginx:alpine");
        service.registerTaskDefinition("restore-fam", List.of(cd), null, null, null,
                null, null, List.of(), REGION);
    }

    private static EcsLoadBalancer loadBalancer() {
        EcsLoadBalancer lb = new EcsLoadBalancer();
        lb.setTargetGroupArn("arn:aws:elasticloadbalancing:" + REGION + ":" + ACCOUNT + ":targetgroup/app/1");
        lb.setContainerName("app");
        lb.setContainerPort(4318);
        return lb;
    }

    /** Docker mode, with a container manager that starts each task straight into RUNNING. */
    private static EcsService dockerModeEcsService(StorageFactory storageFactory,
                                                  EcsLoadBalancerRegistrar registrar) {
        EmulatorConfig config = mock(EmulatorConfig.class, RETURNS_DEEP_STUBS);
        when(config.services().ecs().mock()).thenReturn(false);
        when(config.effectiveBaseUrl()).thenReturn("http://localhost:4566");

        EcsContainerManager containerManager = mock(EcsContainerManager.class);
        when(containerManager.startTask(any(), any(), any(), any())).thenAnswer(invocation -> {
            EcsTask task = invocation.getArgument(0);
            Container container = new Container();
            container.setName("app");
            container.setNetworkBindings(List.of(new NetworkBinding("0.0.0.0", 4318, 4318, "tcp")));
            task.setContainers(List.of(container));
            task.setLastStatus(TaskStatus.RUNNING.name());
            return new EcsTaskHandle(task.getTaskArn(), Map.of(), Map.of());
        });

        return new EcsService(
                new RegionResolver(REGION, ACCOUNT),
                containerManager,
                config,
                registrar,
                storageFactory,
                null);
    }

    @Test
    void nothingIsPendingWhenNoServiceIsPersisted() {
        EcsService service = ecsService(new SharedStorageFactory());
        service.initializeStorage();

        service.restorePersistedRuntime();

        assertTrue(service.pendingRestoredServices().isEmpty(),
                "a Floci with no persisted service is healthy at once");
    }

    @Test
    void aServiceWhoseRestoreThrowsStaysPendingWithTheExceptionMessageAndDoesNotBlockTheOthers() {
        SharedStorageFactory storageFactory = new SharedStorageFactory();

        EcsService before = ecsService(storageFactory);
        before.initializeStorage();
        ContainerDefinition cd = new ContainerDefinition();
        cd.setName("app");
        cd.setImage("nginx:alpine");
        before.registerTaskDefinition("restore-fam", List.of(cd), null, null, null,
                null, null, List.of(), REGION);
        before.createCluster("restore-cluster", REGION);
        before.createService("restore-cluster", "good-svc", "restore-fam", 1,
                LaunchType.FARGATE, List.of(), null, REGION);

        // A service on a cluster the state no longer holds: its reconcile throws.
        EcsServiceModel broken = new EcsServiceModel();
        broken.setServiceName("broken-svc");
        broken.setServiceArn("arn:aws:ecs:" + REGION + ":" + ACCOUNT + ":service/ghost-cluster/broken-svc");
        broken.setStatus("ACTIVE");
        broken.setDesiredCount(1);
        broken.setTaskDefinition("restore-fam");
        broken.setLaunchType(LaunchType.FARGATE);
        storageFactory.servicesStore()
                .putForAccount(ACCOUNT, REGION + "::ghost-cluster/broken-svc", broken);

        EcsService restored = ecsService(storageFactory);
        restored.initializeStorage();
        restored.restorePersistedRuntime();

        Map<String, String> pending = restored.pendingRestoredServices().orElseThrow();
        assertTrue(pending.containsKey("broken-svc"), "the failing service stays pending: " + pending);
        assertTrue(pending.get("broken-svc").contains("ghost-cluster"),
                "its reason is the exception's message: " + pending.get("broken-svc"));

        restored.reconcile();

        assertFalse(restored.pendingRestoredServices().orElseThrow().containsKey("good-svc"),
                "the failing service never blocks the others");
    }

    private static EcsService ecsService(StorageFactory storageFactory) {
        EmulatorConfig config = mock(EmulatorConfig.class, RETURNS_DEEP_STUBS);
        when(config.services().ecs().mock()).thenReturn(true);
        when(config.effectiveBaseUrl()).thenReturn("http://localhost:4566");

        EcsContainerManager containerManager = mock(EcsContainerManager.class);
        when(containerManager.startTask(any(), any(), any(), anyString()))
                .thenReturn(mock(EcsTaskHandle.class));

        return new EcsService(
                new RegionResolver(REGION, ACCOUNT),
                containerManager,
                config,
                mock(EcsLoadBalancerRegistrar.class),
                storageFactory,
                null);
    }

    private static final class SharedStorageFactory extends StorageFactory {

        private final Map<String, AccountAwareStorageBackend<?>> stores = new HashMap<>();

        private SharedStorageFactory() {
            super(null, null);
        }

        @SuppressWarnings("unchecked")
        AccountAwareStorageBackend<EcsServiceModel> servicesStore() {
            return (AccountAwareStorageBackend<EcsServiceModel>) stores.computeIfAbsent(
                    "ecs-services.json", ignored -> AccountAwareStorageBackend.inMemory(ACCOUNT));
        }

        @Override
        @SuppressWarnings("unchecked")
        public <V> AccountAwareStorageBackend<V> create(String serviceName,
                                                       String fileName,
                                                       TypeReference<Map<String, V>> typeReference) {
            return (AccountAwareStorageBackend<V>) stores.computeIfAbsent(fileName,
                    ignored -> AccountAwareStorageBackend.inMemory(ACCOUNT));
        }
    }
}

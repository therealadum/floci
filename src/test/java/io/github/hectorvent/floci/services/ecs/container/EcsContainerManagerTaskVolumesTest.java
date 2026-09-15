package io.github.hectorvent.floci.services.ecs.container;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.core.common.docker.ContainerBuilder;
import io.github.hectorvent.floci.core.common.docker.ContainerDetector;
import io.github.hectorvent.floci.core.common.docker.ContainerLifecycleManager;
import io.github.hectorvent.floci.core.common.docker.ContainerLifecycleManager.ContainerInfo;
import io.github.hectorvent.floci.core.common.docker.ContainerLogStreamer;
import io.github.hectorvent.floci.core.common.docker.LaunchedContainerAwsEnv;
import io.github.hectorvent.floci.services.ecr.registry.EcrRegistryManager;
import io.github.hectorvent.floci.services.ecs.model.ContainerDefinition;
import io.github.hectorvent.floci.services.ecs.model.EcsTask;
import io.github.hectorvent.floci.services.ecs.model.EfsVolumeConfiguration;
import io.github.hectorvent.floci.services.ecs.model.MountPoint;
import io.github.hectorvent.floci.services.ecs.model.TaskDefinition;
import io.github.hectorvent.floci.services.ecs.model.Volume;
import io.github.hectorvent.floci.services.secretsmanager.SecretsManagerService;
import io.github.hectorvent.floci.services.ssm.SsmService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.RETURNS_SELF;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * A task volume with neither {@code host} nor {@code efsVolumeConfiguration} is, on Fargate, a
 * task-scoped bind mount: an empty data volume shared by every container of the task that mounts
 * it, whose data is removed when the task stops. Locally it is one Docker named volume per task,
 * labelled with the task's identity, mounted into each container per its mountPoint and removed
 * with the task.
 */
class EcsContainerManagerTaskVolumesTest {

    private static final String REGION = "us-east-1";
    private static final String TASK_ID = "grafana1";

    private ContainerBuilder.Builder builder;
    private ContainerLifecycleManager lifecycleManager;
    private EcsContainerManager manager;

    @BeforeEach
    void setUp() {
        builder = mock(ContainerBuilder.Builder.class, RETURNS_SELF);
        ContainerBuilder containerBuilder = mock(ContainerBuilder.class);
        when(containerBuilder.newContainer(anyString())).thenReturn(builder);

        lifecycleManager = mock(ContainerLifecycleManager.class);
        when(lifecycleManager.createAndStart(any())).thenReturn(new ContainerInfo("docker-id", Map.of()));

        EmulatorConfig config = mock(EmulatorConfig.class, RETURNS_DEEP_STUBS);
        RegionResolver regionResolver = mock(RegionResolver.class);
        when(regionResolver.getAccountId()).thenReturn("000000000004");
        LaunchedContainerAwsEnv awsEnv = mock(LaunchedContainerAwsEnv.class);
        when(awsEnv.sdkBaselineEnv(any(), any())).thenReturn(List.of());
        EcrRegistryManager ecr = mock(EcrRegistryManager.class);
        when(ecr.rewriteImageUri(anyString())).thenAnswer(inv -> inv.getArgument(0));

        manager = new EcsContainerManager(containerBuilder, lifecycleManager, mock(ContainerLogStreamer.class),
                mock(ContainerDetector.class), config, regionResolver, awsEnv, mock(SsmService.class),
                mock(SecretsManagerService.class), ecr);
    }

    @Test
    void containersSharingABareVolumeMountTheSameNamedVolumeWithTheirOwnAccessMode() {
        EcsTaskHandle handle = manager.startTask(task(), grafanaTask(), List.of(), REGION);

        String volume = EcsContainerManager.taskVolumeName(TASK_ID, "dashboards");

        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, String>> labels = ArgumentCaptor.forClass(Map.class);
        verify(lifecycleManager, times(1)).ensureVolume(eq(volume), labels.capture());
        assertEquals("ecs", labels.getValue().get("io.floci.service"));
        assertEquals(TASK_ID, labels.getValue().get("io.floci.resource-id"));
        assertEquals("000000000004", labels.getValue().get("io.floci.account"));

        verify(builder, times(1)).withNamedVolume(volume, "/etc/grafana/provisioning/dashboards", true);
        verify(builder, times(1)).withNamedVolume(volume, "/provisioning/dashboards", false);
        verify(builder, never()).withBind(any(), any());
        verify(builder, never()).withReadOnlyBind(any(), any());

        assertEquals(List.of(volume), handle.getVolumeNames());
    }

    @Test
    void stoppingTheTaskRemovesItsScratchVolume() {
        EcsTaskHandle handle = manager.startTask(task(), grafanaTask(), List.of(), REGION);
        String volume = EcsContainerManager.taskVolumeName(TASK_ID, "dashboards");

        manager.stopTaskAndCollectExitCodes(handle);

        verify(lifecycleManager, times(1)).removeVolume(volume);
    }

    @Test
    void cleaningUpAStoppedTaskRemovesItsScratchVolume() {
        EcsTaskHandle handle = manager.startTask(task(), grafanaTask(), List.of(), REGION);
        String volume = EcsContainerManager.taskVolumeName(TASK_ID, "dashboards");

        manager.cleanupStoppedTask(handle);

        verify(lifecycleManager, times(1)).removeVolume(volume);
    }

    @Test
    void hostAndEfsVolumesAreUnchanged() {
        ContainerDefinition app = new ContainerDefinition();
        app.setName("app");
        app.setImage("app:latest");
        app.setMountPoints(List.of(
                new MountPoint("host-vol", "/host", true),
                new MountPoint("efs-vol", "/mnt/efs", false)));

        TaskDefinition taskDef = new TaskDefinition();
        taskDef.setFamily("mixed");
        taskDef.setContainerDefinitions(List.of(app));
        taskDef.setVolumes(List.of(
                new Volume("host-vol", "/abs/host"),
                new Volume("efs-vol", null, new EfsVolumeConfiguration("fs-abc", null, null, null, null, null))));

        EcsTaskHandle handle = manager.startTask(task(), taskDef, List.of(), REGION);

        verify(builder, times(1)).withReadOnlyBind("/abs/host", "/host");
        verify(builder, times(1)).withNamedVolume(
                EcsContainerManager.efsVolumeName("fs-abc", null, null), "/mnt/efs", false);
        verify(lifecycleManager, never()).ensureVolume(anyString(), anyMap());
        assertEquals(List.of(), handle.getVolumeNames());

        manager.stopTaskAndCollectExitCodes(handle);
        verify(lifecycleManager, never()).removeVolume(anyString());
    }

    private static EcsTask task() {
        EcsTask task = new EcsTask();
        task.setTaskArn("arn:aws:ecs:" + REGION + ":000000000004:task/c1/" + TASK_ID);
        return task;
    }

    /** Grafana reads provisioning a sync sidecar writes, through one bare task volume. */
    private static TaskDefinition grafanaTask() {
        ContainerDefinition app = new ContainerDefinition();
        app.setName("app");
        app.setImage("grafana:13");
        app.setMountPoints(List.of(new MountPoint("dashboards", "/etc/grafana/provisioning/dashboards", true)));

        ContainerDefinition sync = new ContainerDefinition();
        sync.setName("grafana-sync");
        sync.setImage("grafana-sync:1");
        sync.setMountPoints(List.of(new MountPoint("dashboards", "/provisioning/dashboards", false)));

        TaskDefinition taskDef = new TaskDefinition();
        taskDef.setFamily("grafana");
        taskDef.setContainerDefinitions(List.of(app, sync));
        taskDef.setVolumes(List.of(new Volume("dashboards", null, null)));
        return taskDef;
    }
}

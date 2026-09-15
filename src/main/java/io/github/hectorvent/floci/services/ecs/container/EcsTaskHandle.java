package io.github.hectorvent.floci.services.ecs.container;

import java.io.Closeable;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Holds the runtime Docker container IDs for a running ECS task.
 * Maps container names to Docker IDs and Docker IDs to their log stream handles, and names the
 * Docker volumes backing the task's scratch volumes, which are removed with the task.
 */
public class EcsTaskHandle {

    private final String taskArn;
    private final Map<String, String> containerIds;   // containerName → dockerId
    private final Map<String, Closeable> logStreamsByContainerId;
    private final List<String> volumeNames;

    public EcsTaskHandle(String taskArn, Map<String, String> containerIds,
                         Map<String, Closeable> logStreamsByContainerId) {
        this(taskArn, containerIds, logStreamsByContainerId, List.of());
    }

    public EcsTaskHandle(String taskArn, Map<String, String> containerIds,
                         Map<String, Closeable> logStreamsByContainerId, List<String> volumeNames) {
        this.taskArn = taskArn;
        this.containerIds = new LinkedHashMap<>(containerIds);
        this.logStreamsByContainerId = new LinkedHashMap<>(logStreamsByContainerId);
        this.volumeNames = List.copyOf(volumeNames);
    }

    public String getTaskArn() { return taskArn; }
    /** Docker volumes backing the task's scratch volumes; removed when the task stops. */
    public List<String> getVolumeNames() { return volumeNames; }
    public Map<String, String> getContainerIds() { return containerIds; }
    public Map<String, Closeable> getLogStreamsByContainerId() { return logStreamsByContainerId; }

    /** Removes and returns the log stream that no longer needs task-level ownership. */
    public Closeable removeLogStream(String containerId) {
        return logStreamsByContainerId.remove(containerId);
    }

    public boolean hasOpenLogStreams() {
        return !logStreamsByContainerId.isEmpty();
    }
}

package io.github.hectorvent.floci.services.ecs.model;

import io.quarkus.runtime.annotations.RegisterForReflection;

/**
 * The compact view of a {@link ServiceRevision} that {@code DescribeServiceDeployments}
 * embeds as {@code targetServiceRevision} and {@code sourceServiceRevisions[]}. The task
 * counts are the live counts of the service the revision belongs to, as on AWS.
 *
 * @param arn ARN of the service revision
 * @param requestedTaskCount the service's desired count for this revision
 * @param runningTaskCount tasks of this revision currently running
 * @param pendingTaskCount tasks of this revision still coming up
 */
@RegisterForReflection
public record ServiceRevisionSummary(
        String arn,
        int requestedTaskCount,
        int runningTaskCount,
        int pendingTaskCount
) {
}

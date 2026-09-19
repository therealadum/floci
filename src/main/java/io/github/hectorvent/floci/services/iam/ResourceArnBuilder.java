package io.github.hectorvent.floci.services.iam;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.core.common.AwsArnUtils;
import io.github.hectorvent.floci.core.common.IamConditionContextResolver;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.MediaType;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Constructs the target resource ARN for a request so the policy evaluator
 * can match it against Resource patterns in policy documents.
 *
 * Returns {@code *} when the resource cannot be determined, which matches
 * permissive wildcard policies.
 */
@ApplicationScoped
public class ResourceArnBuilder {

    /** Where the decoded form body is held for the life of one request. */
    private static final String BUFFERED_FORM_BODY = "floci.bufferedFormBody";

    private final ObjectMapper objectMapper;

    @Inject
    public ResourceArnBuilder(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public ResourceArnBuilder() {
        this(new ObjectMapper());
    }

    public String build(String credentialScope, ContainerRequestContext ctx,
                        String region, String accountId) {
        List<String> list = buildResources(credentialScope, ctx, region, accountId);
        return list.isEmpty() ? "*" : list.getFirst();
    }

    public List<String> buildResources(String credentialScope, ContainerRequestContext ctx,
                                       String region, String accountId) {
        if (credentialScope == null) {
            return List.of("*");
        }
        String path = ctx.getUriInfo().getPath();
        return switch (credentialScope) {
            case "s3"             -> List.of(buildS3Arn(path));
            case "lambda"         -> List.of(buildLambdaArn(path, region, accountId));
            case "sqs"            -> List.of(buildSqsArn(ctx, region, accountId));
            case "sns"            -> List.of(buildSnsArn(ctx, region, accountId));
            case "dynamodb"       -> buildDynamoDbArns(ctx, region, accountId);
            case "kinesis"        -> List.of(buildKinesisArn(ctx, region, accountId));
            case "secretsmanager" -> List.of(buildSecretsManagerArn(ctx, region, accountId));
            case "ssm"            -> List.of(buildSsmArn(ctx, region, accountId));
            case "kms"            -> List.of(buildKmsArn(ctx, path, region, accountId));
            case "sts"            -> List.of(buildStsArn(ctx));
            default               -> List.of("*");
        };
    }

    // ── S3 ──────────────────────────────────────────────────────────────────────
    private String buildS3Arn(String path) {
        // path: /bucket or /bucket/key
        String stripped = path.startsWith("/") ? path.substring(1) : path;
        if (stripped.isEmpty()) {
            return AwsArnUtils.Arn.of("s3", "", "", "*").toString();
        }
        int slash = stripped.indexOf('/');
        if (slash < 0) {
            return AwsArnUtils.Arn.of("s3", "", "", stripped).toString();
        }
        return AwsArnUtils.Arn.of("s3", "", "", stripped).toString();
    }

    // ── Lambda ──────────────────────────────────────────────────────────────────
    private String buildLambdaArn(String path, String region, String accountId) {
        // path: /2015-03-31/functions/name or similar
        String name = extractSegmentAfter(path, "functions");
        if (name == null) return "*";
        // strip qualifier if present
        int colon = name.indexOf(':');
        if (colon > 0) name = name.substring(0, colon);
        return AwsArnUtils.Arn.of("lambda", region, accountId, "function:" + name).toString();
    }

    // ── SQS ─────────────────────────────────────────────────────────────────────
    private String buildSqsArn(ContainerRequestContext ctx, String region, String accountId) {
        String queueUrl = ctx.getUriInfo().getQueryParameters().getFirst("QueueUrl");
        if (queueUrl == null) {
            // Try form param for Query-protocol
            queueUrl = firstFormParam(ctx, "QueueUrl");
        }
        if (queueUrl == null) {
            JsonNode json = readJsonBody(ctx);
            if (json != null && json.isObject()) {
                if (json.hasNonNull("QueueUrl")) {
                    queueUrl = json.get("QueueUrl").asText().trim();
                } else if (json.hasNonNull("QueueName")) {
                    String queueName = json.get("QueueName").asText().trim();
                    if (!queueName.isEmpty()) {
                        return AwsArnUtils.Arn.of("sqs", region, accountId, queueName).toString();
                    }
                }
            }
        }
        if (queueUrl != null && !queueUrl.isEmpty()) {
            String queueName = queueUrl.substring(queueUrl.lastIndexOf('/') + 1);
            return AwsArnUtils.Arn.of("sqs", region, accountId, queueName).toString();
        }
        return AwsArnUtils.Arn.of("sqs", region, accountId, "*").toString();
    }

    // ── SNS ─────────────────────────────────────────────────────────────────────
    private String buildSnsArn(ContainerRequestContext ctx, String region, String accountId) {
        String topicArn = firstFormParam(ctx, "TopicArn");
        if (topicArn == null) {
            JsonNode json = readJsonBody(ctx);
            if (json != null && json.isObject() && json.hasNonNull("TopicArn")) {
                topicArn = json.get("TopicArn").asText().trim();
            }
        }
        return (topicArn != null && !topicArn.isEmpty())
                ? topicArn
                : AwsArnUtils.Arn.of("sns", region, accountId, "*").toString();
    }

    // ── DynamoDB ─────────────────────────────────────────────────────────────────
    private String buildDynamoDbArn(ContainerRequestContext ctx, String region, String accountId) {
        List<String> arns = buildDynamoDbArns(ctx, region, accountId);
        return arns.isEmpty() ? "*" : arns.getFirst();
    }

    private List<String> buildDynamoDbArns(ContainerRequestContext ctx, String region, String accountId) {
        JsonNode json = readJsonBody(ctx);
        if (json != null && json.isObject()) {
            if (json.hasNonNull("TableName")) {
                String tableName = json.get("TableName").asText().trim();
                if (!tableName.isEmpty()) {
                    return List.of(toDynamoDbTableArn(tableName, region, accountId));
                }
            }
            if (json.path("TableCreationParameters").hasNonNull("TableName")) {
                var tableName = json.path("TableCreationParameters").get("TableName").asText().trim();
                if (!tableName.isEmpty()) {
                    return List.of(toDynamoDbTableArn(tableName, region, accountId));
                }
            }
            if (json.hasNonNull("ResourceArn")) {
                String resourceArn = json.get("ResourceArn").asText().trim();
                if (!resourceArn.isEmpty()) {
                    return List.of(resourceArn);
                }
            }
            if (json.hasNonNull("TableArn")) {
                String tableArn = json.get("TableArn").asText().trim();
                if (!tableArn.isEmpty()) {
                    return List.of(tableArn);
                }
            }
            if (json.hasNonNull("StreamArn")) {
                String streamArn = json.get("StreamArn").asText().trim();
                if (!streamArn.isEmpty()) {
                    return List.of(streamArn);
                }
            }
            if (json.hasNonNull("ExportArn")) {
                String exportArn = json.get("ExportArn").asText().trim();
                if (!exportArn.isEmpty()) {
                    return List.of(exportArn);
                }
            }
            if (json.hasNonNull("ImportArn")) {
                var importArn = json.get("ImportArn").asText().trim();
                if (!importArn.isEmpty()) {
                    return List.of(importArn);
                }
            }
            if (json.hasNonNull("RequestItems") && json.get("RequestItems").isObject()) {
                Set<String> arns = new LinkedHashSet<>();
                var fieldNames = json.get("RequestItems").fieldNames();
                while (fieldNames.hasNext()) {
                    String table = fieldNames.next().trim();
                    if (!table.isEmpty()) {
                        arns.add(toDynamoDbTableArn(table, region, accountId));
                    }
                }
                if (!arns.isEmpty()) {
                    return new ArrayList<>(arns);
                }
            }
            if (json.hasNonNull("TransactItems") && json.get("TransactItems").isArray()) {
                Set<String> arns = new LinkedHashSet<>();
                JsonNode items = json.get("TransactItems");
                for (JsonNode item : items) {
                    String t = null;
                    if (item.hasNonNull("Put") && item.get("Put").hasNonNull("TableName")) {
                        t = item.get("Put").get("TableName").asText();
                    } else if (item.hasNonNull("Delete") && item.get("Delete").hasNonNull("TableName")) {
                        t = item.get("Delete").get("TableName").asText();
                    } else if (item.hasNonNull("Update") && item.get("Update").hasNonNull("TableName")) {
                        t = item.get("Update").get("TableName").asText();
                    } else if (item.hasNonNull("ConditionCheck") && item.get("ConditionCheck").hasNonNull("TableName")) {
                        t = item.get("ConditionCheck").get("TableName").asText();
                    } else if (item.hasNonNull("Get") && item.get("Get").hasNonNull("TableName")) {
                        t = item.get("Get").get("TableName").asText();
                    }
                    if (t != null) {
                        t = t.trim();
                        if (!t.isEmpty()) {
                            arns.add(toDynamoDbTableArn(t, region, accountId));
                        }
                    }
                }
                if (!arns.isEmpty()) {
                    return new ArrayList<>(arns);
                }
            }
            if (json.hasNonNull("Statement")) {
                String stmt = json.get("Statement").asText().trim();
                String table = extractDynamoDbTableFromPartiQL(stmt);
                if (table != null && !table.isEmpty()) {
                    return List.of(toDynamoDbTableArn(table, region, accountId));
                }
            }
            if (json.hasNonNull("Statements") && json.get("Statements").isArray()) {
                Set<String> arns = new LinkedHashSet<>();
                for (JsonNode s : json.get("Statements")) {
                    if (s.hasNonNull("Statement")) {
                        String table = extractDynamoDbTableFromPartiQL(s.get("Statement").asText());
                        if (table != null && !table.isEmpty()) {
                            arns.add(toDynamoDbTableArn(table, region, accountId));
                        }
                    }
                }
                if (!arns.isEmpty()) {
                    return new ArrayList<>(arns);
                }
            }
            if (json.hasNonNull("TransactStatements") && json.get("TransactStatements").isArray()) {
                Set<String> arns = new LinkedHashSet<>();
                for (JsonNode s : json.get("TransactStatements")) {
                    if (s.hasNonNull("Statement")) {
                        String table = extractDynamoDbTableFromPartiQL(s.get("Statement").asText());
                        if (table != null && !table.isEmpty()) {
                            arns.add(toDynamoDbTableArn(table, region, accountId));
                        }
                    }
                }
                if (!arns.isEmpty()) {
                    return new ArrayList<>(arns);
                }
            }
        }
        return List.of("*");
    }

    private static String extractDynamoDbTableFromPartiQL(String statement) {
        return io.github.hectorvent.floci.services.dynamodb.DynamoDbPartiQLParser.extractTable(statement);
    }

    private String toDynamoDbTableArn(String tableName, String region, String accountId) {
        if (AwsArnUtils.isArnFor(tableName, "dynamodb")) {
            return tableName;
        }
        return AwsArnUtils.Arn.of("dynamodb", region, accountId, "table/" + tableName).toString();
    }

    // ── Kinesis ──────────────────────────────────────────────────────────────────
    private String buildKinesisArn(ContainerRequestContext ctx, String region, String accountId) {
        JsonNode json = readJsonBody(ctx);
        if (json != null && json.isObject()) {
            if (json.hasNonNull("StreamARN")) {
                String streamArn = json.get("StreamARN").asText().trim();
                if (!streamArn.isEmpty()) {
                    return streamArn;
                }
            }
            if (json.hasNonNull("StreamName")) {
                String streamName = json.get("StreamName").asText().trim();
                if (!streamName.isEmpty()) {
                    if (AwsArnUtils.isArnFor(streamName, "kinesis")) {
                        return streamName;
                    }
                    return AwsArnUtils.Arn.of("kinesis", region, accountId, "stream/" + streamName).toString();
                }
            }
            if (json.hasNonNull("ResourceARN")) {
                String resourceArn = json.get("ResourceARN").asText().trim();
                if (!resourceArn.isEmpty()) {
                    return resourceArn;
                }
            }
        }
        return AwsArnUtils.Arn.of("kinesis", region, accountId, "stream/*").toString();
    }

    // ── Secrets Manager ──────────────────────────────────────────────────────────
    private String buildSecretsManagerArn(ContainerRequestContext ctx, String region, String accountId) {
        JsonNode json = readJsonBody(ctx);
        if (json != null && json.isObject()) {
            if (json.hasNonNull("SecretId")) {
                String secretId = json.get("SecretId").asText().trim();
                if (!secretId.isEmpty()) {
                    if (AwsArnUtils.isArnFor(secretId, "secretsmanager")) {
                        return secretId;
                    }
                    return AwsArnUtils.Arn.of("secretsmanager", region, accountId, "secret:" + secretId).toString();
                }
            }
        }
        return AwsArnUtils.Arn.of("secretsmanager", region, accountId, "secret:*").toString();
    }

    // ── SSM ──────────────────────────────────────────────────────────────────────
    private String buildSsmArn(ContainerRequestContext ctx, String region, String accountId) {
        JsonNode json = readJsonBody(ctx);
        if (json != null && json.isObject()) {
            if (json.hasNonNull("Name")) {
                String name = json.get("Name").asText().trim();
                if (!name.isEmpty()) {
                    if (AwsArnUtils.isArnFor(name, "ssm")) {
                        return name;
                    }
                    String paramResource = name.startsWith("/") ? "parameter" + name : "parameter/" + name;
                    return AwsArnUtils.Arn.of("ssm", region, accountId, paramResource).toString();
                }
            }
        }
        return AwsArnUtils.Arn.of("ssm", region, accountId, "parameter/*").toString();
    }

    // ── KMS ──────────────────────────────────────────────────────────────────────
    private String buildKmsArn(ContainerRequestContext ctx, String path, String region, String accountId) {
        String keyId = extractSegmentAfter(path, "keys");
        if (keyId == null) {
            // KMS is JSON 1.1: every request is a POST to "/" and the key is named by KeyId in the
            // body, never in the path. Without reading it the target of every KMS call was
            // "key/*", which names no key and so can carry no key policy.
            keyId = readKmsKeyId(ctx);
        }
        if (keyId == null) {
            return AwsArnUtils.Arn.of("kms", region, accountId, "key/*").toString();
        }
        if (AwsArnUtils.isArnFor(keyId, "kms")) {
            // A full ARN names the key's own account, which is how a cross-account key is reached.
            return keyId;
        }
        if (keyId.startsWith("alias/")) {
            return AwsArnUtils.Arn.of("kms", region, accountId, keyId).toString();
        }
        return AwsArnUtils.Arn.of("kms", region, accountId, "key/" + keyId).toString();
    }

    private String readKmsKeyId(ContainerRequestContext ctx) {
        JsonNode json = readJsonBody(ctx);
        if (json == null || !json.isObject() || !json.hasNonNull("KeyId")) {
            return null;
        }
        String keyId = json.get("KeyId").asText().trim();
        return keyId.isEmpty() ? null : keyId;
    }

    // ── STS ─────────────────────────────────────────────────────────────────────

    /**
     * The resource of an {@code AssumeRole} is the role being assumed, which is what lets a
     * policy on the role's own account — a resource control policy among them — say who may
     * assume it. Every other STS action names no resource and answers {@code *}.
     */
    private String buildStsArn(ContainerRequestContext ctx) {
        String roleArn = IamConditionContextResolver.formParameters(ctx).get("RoleArn");
        if (roleArn == null) {
            roleArn = firstFormParam(ctx, "RoleArn");
        }
        return roleArn == null || roleArn.isBlank() ? "*" : roleArn.trim();
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────

    private JsonNode readJsonBody(ContainerRequestContext ctx) {
        Object cached = ctx.getProperty("floci.bufferedJsonBody");
        if (cached instanceof JsonNode node) {
            return node;
        }
        InputStream in = ctx.getEntityStream();
        if (in == null) {
            return null;
        }
        byte[] body;
        try {
            body = in.readAllBytes();
        } catch (IOException e) {
            ctx.setEntityStream(new ByteArrayInputStream(new byte[0]));
            return null;
        }
        ctx.setEntityStream(new ByteArrayInputStream(body));
        if (body.length == 0) {
            return null;
        }
        try {
            JsonNode node = objectMapper.readTree(body);
            ctx.setProperty("floci.bufferedJsonBody", node);
            return node;
        } catch (Exception e) {
            return null;
        }
    }

    private String extractSegmentAfter(String path, String segment) {
        String marker = "/" + segment + "/";
        int idx = path.indexOf(marker);
        if (idx < 0) return null;
        String after = path.substring(idx + marker.length());
        // take only the first segment (stop at next /)
        int slash = after.indexOf('/');
        return slash > 0 ? after.substring(0, slash) : after;
    }

    /**
     * One parameter of a Query-protocol request, from the URL when it is there and from the
     * form-encoded body otherwise.
     *
     * <p>An SDK sends a Query-protocol call as a POST with every parameter in the body, which is
     * also the only shape a SigV4 signature covers, so reading the URL alone found nothing on a
     * genuinely signed request: every SNS and SQS target then fell back to the wildcard ARN of
     * the caller's own account, and a topic or queue policy could never be found for it. The body
     * is buffered and put back, exactly as {@code IamActionRegistry} does when it reads
     * {@code Action} out of the same body.</p>
     */
    private String firstFormParam(ContainerRequestContext ctx, String name) {
        String fromUrl = ctx.getUriInfo().getQueryParameters().getFirst(name);
        if (fromUrl != null && !fromUrl.isEmpty()) {
            return fromUrl;
        }
        Map<String, String> form = readFormBody(ctx);
        return form == null ? null : form.get(name);
    }

    @SuppressWarnings("unchecked")
    private Map<String, String> readFormBody(ContainerRequestContext ctx) {
        Object cached = ctx.getProperty(BUFFERED_FORM_BODY);
        if (cached instanceof Map<?, ?> map) {
            return (Map<String, String>) map;
        }
        MediaType mediaType = ctx.getMediaType();
        if (mediaType == null
                || !"application".equalsIgnoreCase(mediaType.getType())
                || !"x-www-form-urlencoded".equalsIgnoreCase(mediaType.getSubtype())) {
            return null;
        }
        InputStream in = ctx.getEntityStream();
        if (in == null) {
            return null;
        }
        byte[] body;
        try {
            body = in.readAllBytes();
        } catch (IOException e) {
            ctx.setEntityStream(new ByteArrayInputStream(new byte[0]));
            return null;
        }
        ctx.setEntityStream(new ByteArrayInputStream(body));
        if (body.length == 0) {
            return null;
        }
        Charset charset = formCharset(mediaType);
        Map<String, String> parameters = new HashMap<>();
        for (String pair : new String(body, charset).split("&")) {
            int equals = pair.indexOf('=');
            if (equals < 0) {
                continue;
            }
            try {
                parameters.putIfAbsent(URLDecoder.decode(pair.substring(0, equals), charset),
                        URLDecoder.decode(pair.substring(equals + 1), charset));
            } catch (RuntimeException e) {
                // A parameter this emulator cannot decode names no resource; the rest still do.
            }
        }
        ctx.setProperty(BUFFERED_FORM_BODY, parameters);
        return parameters;
    }

    private static Charset formCharset(MediaType mediaType) {
        String name = mediaType.getParameters().get("charset");
        if (name == null || name.isBlank()) {
            return StandardCharsets.UTF_8;
        }
        try {
            return Charset.forName(name);
        } catch (RuntimeException e) {
            return StandardCharsets.UTF_8;
        }
    }
}

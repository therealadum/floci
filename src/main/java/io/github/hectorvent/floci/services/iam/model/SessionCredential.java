package io.github.hectorvent.floci.services.iam.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import io.quarkus.runtime.annotations.RegisterForReflection;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RegisterForReflection
@JsonIgnoreProperties(ignoreUnknown = true)
public class SessionCredential {

    private String accessKeyId;
    private String secretAccessKey;
    private String sessionToken;
    private String roleArn;
    private Instant expiration;
    /** Inline session policy passed to AssumeRole/GetFederationToken — further restricts role policies. */
    private String sessionPolicyDocument;
    /**
     * Account of the caller that minted this session, captured at mint time. Used to route
     * temporary credentials that carry no role ARN (e.g. GetSessionToken) back to the caller.
     */
    private String originAccountId;
    /** True when this session belongs to a Floci-launched Lambda container. */
    private boolean lambdaExecutionRole;
    /**
     * The session tags {@code AssumeRole} was given, which are {@code aws:PrincipalTag/<key>} on
     * every request the session then makes.
     */
    private Map<String, String> sessionTags = new LinkedHashMap<>();
    /**
     * The subset of {@link #sessionTags} whose keys were named in {@code TransitiveTagKeys}. They
     * carry into every role this session goes on to assume, and cannot be overwritten there.
     */
    private List<String> transitiveTagKeys = new ArrayList<>();

    public SessionCredential() {}

    public SessionCredential(String accessKeyId, String roleArn, Instant expiration) {
        this.accessKeyId = accessKeyId;
        this.roleArn = roleArn;
        this.expiration = expiration;
    }

    public SessionCredential(String accessKeyId, String roleArn, Instant expiration, String sessionPolicyDocument) {
        this.accessKeyId = accessKeyId;
        this.roleArn = roleArn;
        this.expiration = expiration;
        this.sessionPolicyDocument = sessionPolicyDocument;
    }

    public SessionCredential(String accessKeyId, String secretAccessKey, String roleArn, Instant expiration,
                              String sessionPolicyDocument) {
        this(accessKeyId, secretAccessKey, null, roleArn, expiration, sessionPolicyDocument);
    }

    public SessionCredential(String accessKeyId, String secretAccessKey, String sessionToken, String roleArn,
                              Instant expiration, String sessionPolicyDocument) {
        this.accessKeyId = accessKeyId;
        this.secretAccessKey = secretAccessKey;
        this.sessionToken = sessionToken;
        this.roleArn = roleArn;
        this.expiration = expiration;
        this.sessionPolicyDocument = sessionPolicyDocument;
    }

    public SessionCredential(String accessKeyId, String secretAccessKey, String roleArn, Instant expiration,
                              String sessionPolicyDocument, String originAccountId) {
        this(accessKeyId, secretAccessKey, null, roleArn, expiration, sessionPolicyDocument, originAccountId);
    }

    public SessionCredential(String accessKeyId, String secretAccessKey, String sessionToken, String roleArn,
                              Instant expiration, String sessionPolicyDocument, String originAccountId) {
        this.accessKeyId = accessKeyId;
        this.secretAccessKey = secretAccessKey;
        this.sessionToken = sessionToken;
        this.roleArn = roleArn;
        this.expiration = expiration;
        this.sessionPolicyDocument = sessionPolicyDocument;
        this.originAccountId = originAccountId;
    }

    public String getAccessKeyId() { return accessKeyId; }
    public void setAccessKeyId(String accessKeyId) { this.accessKeyId = accessKeyId; }

    public String getSecretAccessKey() { return secretAccessKey; }
    public void setSecretAccessKey(String secretAccessKey) { this.secretAccessKey = secretAccessKey; }

    public String getSessionToken() { return sessionToken; }
    public void setSessionToken(String sessionToken) { this.sessionToken = sessionToken; }

    public String getRoleArn() { return roleArn; }
    public void setRoleArn(String roleArn) { this.roleArn = roleArn; }

    public Instant getExpiration() { return expiration; }
    public void setExpiration(Instant expiration) { this.expiration = expiration; }

    public String getSessionPolicyDocument() { return sessionPolicyDocument; }
    public void setSessionPolicyDocument(String sessionPolicyDocument) { this.sessionPolicyDocument = sessionPolicyDocument; }

    public String getOriginAccountId() { return originAccountId; }
    public void setOriginAccountId(String originAccountId) { this.originAccountId = originAccountId; }

    public boolean isLambdaExecutionRole() { return lambdaExecutionRole; }
    public void setLambdaExecutionRole(boolean lambdaExecutionRole) { this.lambdaExecutionRole = lambdaExecutionRole; }

    public Map<String, String> getSessionTags() {
        if (sessionTags == null) {
            sessionTags = new LinkedHashMap<>();
        }
        return sessionTags;
    }

    public void setSessionTags(Map<String, String> sessionTags) {
        this.sessionTags = sessionTags == null ? new LinkedHashMap<>() : new LinkedHashMap<>(sessionTags);
    }

    public List<String> getTransitiveTagKeys() {
        if (transitiveTagKeys == null) {
            transitiveTagKeys = new ArrayList<>();
        }
        return transitiveTagKeys;
    }

    public void setTransitiveTagKeys(List<String> transitiveTagKeys) {
        this.transitiveTagKeys = transitiveTagKeys == null ? new ArrayList<>() : new ArrayList<>(transitiveTagKeys);
    }
}

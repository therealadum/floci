package io.github.hectorvent.floci.services.account.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.quarkus.runtime.annotations.RegisterForReflection;

import java.time.Instant;

/**
 * What {@code GetAccountInformation} answers about one account: its id, its name, and the date
 * it was created.
 *
 * <p>Stored for an account that belongs to no organization, so the created date it answers is
 * the same on every call. An account that is an organization member answers from the
 * organization's own record instead and nothing is stored for it.</p>
 */
@RegisterForReflection
@JsonIgnoreProperties(ignoreUnknown = true)
public class AccountInformation {
    @JsonProperty("AccountId")
    private String accountId;
    @JsonProperty("AccountName")
    private String accountName;
    @JsonProperty("AccountCreatedDate")
    private Instant accountCreatedDate;

    public AccountInformation() {
    }

    public AccountInformation(String accountId, String accountName, Instant accountCreatedDate) {
        this.accountId = accountId;
        this.accountName = accountName;
        this.accountCreatedDate = accountCreatedDate;
    }

    public String getAccountId() {
        return accountId;
    }

    public void setAccountId(String accountId) {
        this.accountId = accountId;
    }

    public String getAccountName() {
        return accountName;
    }

    public void setAccountName(String accountName) {
        this.accountName = accountName;
    }

    public Instant getAccountCreatedDate() {
        return accountCreatedDate;
    }

    public void setAccountCreatedDate(Instant accountCreatedDate) {
        this.accountCreatedDate = accountCreatedDate;
    }
}

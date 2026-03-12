package org.ekstep.analytics.hadoop;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.AnonymousAWSCredentials;
import com.amazonaws.auth.BasicSessionCredentials;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClient;
import com.amazonaws.services.securitytoken.model.AssumeRoleWithWebIdentityRequest;
import com.amazonaws.services.securitytoken.model.AssumeRoleWithWebIdentityResult;
import com.amazonaws.services.securitytoken.model.Credentials;

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.apache.hadoop.conf.Configuration;

/**
 * AWS credentials provider for EKS IRSA (IAM Roles for Service Accounts).
 * Reads the projected web identity token and assumes an IAM role via STS
 * AssumeRoleWithWebIdentity. Automatically refreshes credentials before expiry.
 *
 * Compatible with hadoop-aws-2.7.x and aws-java-sdk-1.7.x.
 *
 * Env vars required (auto-set by EKS IRSA):
 *   AWS_WEB_IDENTITY_TOKEN_FILE - path to the OIDC token file
 *   AWS_ROLE_ARN - IAM role ARN to assume
 * Optional:
 *   AWS_ROLE_SESSION_NAME - session name (default: spark-s3a-session)
 *   AWS_REGION / AWS_DEFAULT_REGION - for regional STS endpoint
 */
public class OidcCredentialsProvider implements AWSCredentialsProvider {

    private volatile BasicSessionCredentials credentials;
    private volatile long expirationMillis;

    public OidcCredentialsProvider() {
        refresh();
    }

    /** Constructor tried first by hadoop-aws-2.7.x */
    public OidcCredentialsProvider(URI uri, Configuration conf) {
        this();
    }

    @Override
    public AWSCredentials getCredentials() {
        // Refresh 5 minutes before expiry
        if (credentials == null || System.currentTimeMillis() > expirationMillis - 300000) {
            refresh();
        }
        return credentials;
    }

    @Override
    public synchronized void refresh() {
        try {
            String tokenFile = System.getenv("AWS_WEB_IDENTITY_TOKEN_FILE");
            String roleArn = System.getenv("AWS_ROLE_ARN");
            String sessionName = System.getenv("AWS_ROLE_SESSION_NAME");
            if (sessionName == null || sessionName.isEmpty()) {
                sessionName = "spark-s3a-session";
            }

            String token = new String(Files.readAllBytes(Paths.get(tokenFile)), "UTF-8");

            AWSSecurityTokenServiceClient stsClient = new AWSSecurityTokenServiceClient(
                new AnonymousAWSCredentials());

            String region = System.getenv("AWS_REGION");
            if (region == null) region = System.getenv("AWS_DEFAULT_REGION");
            if (region != null && !region.isEmpty()) {
                stsClient.setEndpoint("https://sts." + region + ".amazonaws.com");
            }

            AssumeRoleWithWebIdentityRequest request = new AssumeRoleWithWebIdentityRequest()
                .withRoleArn(roleArn)
                .withWebIdentityToken(token)
                .withRoleSessionName(sessionName);

            AssumeRoleWithWebIdentityResult result = stsClient.assumeRoleWithWebIdentity(request);
            Credentials creds = result.getCredentials();

            this.credentials = new BasicSessionCredentials(
                creds.getAccessKeyId(),
                creds.getSecretAccessKey(),
                creds.getSessionToken()
            );
            this.expirationMillis = creds.getExpiration().getTime();
        } catch (Exception e) {
            throw new RuntimeException("Failed to assume role with web identity", e);
        }
    }
}

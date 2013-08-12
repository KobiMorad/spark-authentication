package com.qmetric.spark.authentication;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import spark.Filter;
import spark.Request;
import spark.Response;
import spark.utils.SparkUtils;

public class BasicAuthenticationFilter extends Filter
{
    private static final String BASIC_AUTHENTICATION_TYPE = "Basic";

    private static final int NUMBER_OF_AUTHENTICATION_FIELDS = 2;

    private final AuthenticationDetails authenticationDetails;

    public BasicAuthenticationFilter(final AuthenticationDetails authenticationDetails)
    {
        this(SparkUtils.ALL_PATHS, authenticationDetails);
    }

    public BasicAuthenticationFilter(final String path, final AuthenticationDetails authenticationDetails)
    {
        super(path);
        this.authenticationDetails = authenticationDetails;
    }

    @Override
    public void handle(final Request request, final Response response)
    {
        final String encodedHeader = StringUtils.substringAfter(request.headers("Authorization"), "Basic");

        if (notAuthenticatedWith(credentialsFrom(encodedHeader)))
        {
            response.header("WWW-Authenticate", BASIC_AUTHENTICATION_TYPE);
            halt(401);
        }
    }

    private String[] credentialsFrom(final String encodedHeader)
    {
        return StringUtils.split(encodedHeader != null ? decodeHeader(encodedHeader) : null, ":");
    }

    private String decodeHeader(final String encodedHeader)
    {
        return new String(Base64.decodeBase64(encodedHeader));
    }

    private boolean notAuthenticatedWith(final String[] credentials)
    {
        return !authenticatedWith(credentials);
    }

    private boolean authenticatedWith(final String[] credentials)
    {
        if (credentials != null && credentials.length == NUMBER_OF_AUTHENTICATION_FIELDS)
        {
            final String submittedUsername = credentials[0];
            final String submittedPassword = credentials[1];

            return StringUtils.equals(submittedUsername, authenticationDetails.username) && StringUtils.equals(submittedPassword, new String(authenticationDetails.password));
        }
        else
        {
            return false;
        }
    }
}

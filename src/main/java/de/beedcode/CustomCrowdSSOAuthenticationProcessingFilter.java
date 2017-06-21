package de.beedcode;

import com.atlassian.crowd.integration.http.HttpAuthenticator;
import com.atlassian.crowd.integration.springsecurity.CrowdSSOAuthenticationProcessingFilter;
import com.atlassian.crowd.integration.springsecurity.CrowdSSOAuthenticationToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class CustomCrowdSSOAuthenticationProcessingFilter extends CrowdSSOAuthenticationProcessingFilter {
    private static final Logger logger = LoggerFactory.getLogger(CustomCrowdSSOAuthenticationProcessingFilter.class);

    private HttpAuthenticator httpAuthenticator;

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult)
            throws IOException, ServletException {
        storeTokenIfCrowd(request, response, authResult);
        super.successfulAuthentication(request, response, chain, authResult);
    }

    public void setHttpAuthenticator(HttpAuthenticator httpAuthenticator) {
        this.httpAuthenticator = httpAuthenticator;
        super.setHttpAuthenticator(httpAuthenticator);
    }

    private void storeTokenIfCrowd(HttpServletRequest request, HttpServletResponse response, Authentication authResult) {
        if ( authResult instanceof CrowdSSOAuthenticationToken && authResult.getCredentials() != null )
        {
            try {
                httpAuthenticator.setPrincipalToken(request, response, authResult.getCredentials().toString());
            } catch (Exception var5) {
                logger.error("Unable to set Crowd SSO token", var5);
            }
        }
    }
}
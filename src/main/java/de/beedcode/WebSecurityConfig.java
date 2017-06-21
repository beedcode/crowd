package de.beedcode;

import com.atlassian.crowd.integration.http.HttpAuthenticator;
import com.atlassian.crowd.integration.http.HttpAuthenticatorImpl;
import com.atlassian.crowd.integration.springsecurity.CrowdAuthenticationProvider;
import com.atlassian.crowd.integration.springsecurity.CrowdSSOAuthenticationProcessingFilter;
import com.atlassian.crowd.integration.springsecurity.RemoteCrowdAuthenticationProvider;
import com.atlassian.crowd.integration.springsecurity.UsernameStoringAuthenticationFailureHandler;
import com.atlassian.crowd.integration.springsecurity.user.CrowdUserDetailsService;
import com.atlassian.crowd.integration.springsecurity.user.CrowdUserDetailsServiceImpl;
import com.atlassian.crowd.service.AuthenticationManager;
import com.atlassian.crowd.service.GroupManager;
import com.atlassian.crowd.service.cache.*;
import com.atlassian.crowd.service.soap.client.SecurityServerClient;
import com.atlassian.crowd.service.soap.client.SecurityServerClientImpl;
import com.atlassian.crowd.service.soap.client.SoapClientProperties;
import com.atlassian.crowd.service.soap.client.SoapClientPropertiesImpl;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

@Configuration
@EnableWebSecurity(debug = false)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private CrowdSSOAuthenticationProcessingFilter filter;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authenticationProvider(crowdAuthenticationProvider())
                .addFilter(crowdSSOAuthenticationProcessingFilter())
                .authorizeRequests()
                .antMatchers("/", "/home").permitAll()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .loginPage("/login")
                .permitAll()
                .and()
                .logout()
                .permitAll();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(crowdAuthenticationProvider());
    }

    @Bean
    public CrowdSSOAuthenticationProcessingFilter crowdSSOAuthenticationProcessingFilter() throws Exception {
        filter = new CustomCrowdSSOAuthenticationProcessingFilter();
        filter.setHttpAuthenticator(httpAuthenticator());
        filter.setAuthenticationManager(authenticationManager());
        filter.setAuthenticationFailureHandler(authenticationFailureHandler());
        filter.setAuthenticationSuccessHandler(authenticationSuccessHandler());
        filter.setFilterProcessesUrl("/j_security_check");
        filter.setUsernameParameter("j_username");
        filter.setPasswordParameter("j_password");
        return filter;
    }

    @Bean
    public AuthenticationFailureHandler authenticationFailureHandler() {
        UsernameStoringAuthenticationFailureHandler failureHandler = new UsernameStoringAuthenticationFailureHandler();
        failureHandler.setDefaultFailureUrl("/login?error=true");
        return failureHandler;
    }

    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler() {
        SavedRequestAwareAuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
        successHandler.setDefaultTargetUrl("/home");
        return successHandler;
    }

    @Bean
    CrowdAuthenticationProvider crowdAuthenticationProvider() throws IOException {
        return new RemoteCrowdAuthenticationProvider(crowdAuthenticationManager(), httpAuthenticator(), crowdUserDetailsService());
    }

    @Bean()
    public HttpAuthenticator httpAuthenticator() throws IOException {
        return new HttpAuthenticatorImpl(crowdAuthenticationManager());
    }

    @Bean
    public AuthenticationManager crowdAuthenticationManager() throws IOException {
        return new SimpleAuthenticationManager(securityServerClient());
    }

    @Bean
    public CrowdUserDetailsService crowdUserDetailsService() throws IOException {
        CrowdUserDetailsServiceImpl crowdUserDetailsService = new CrowdUserDetailsServiceImpl();
        crowdUserDetailsService.setUserManager(userManager());
        crowdUserDetailsService.setAuthorityPrefix("");
        crowdUserDetailsService.setGroupMembershipManager(new CachingGroupMembershipManager(securityServerClient(), userManager(), groupManager(), cache()));
        return crowdUserDetailsService;
    }

    @Bean
    public CachingUserManager userManager() throws IOException {
        return new CachingUserManager(securityServerClient(), cache());
    }

    @Bean
    public GroupManager groupManager() throws IOException {
        return new CachingGroupManager(securityServerClient(), cache());
    }

    @Bean
    public SecurityServerClient securityServerClient() throws IOException {
        return new SecurityServerClientImpl(soapClientProperties());
    }

    @Bean
    public SoapClientProperties soapClientProperties() throws IOException {
        Properties prop = new Properties();
        try (InputStream in = Thread.currentThread().getContextClassLoader().getResourceAsStream("crowd.properties")) {
            prop.load(in);
        }
        return SoapClientPropertiesImpl.newInstanceFromProperties(prop);
    }

    @Bean
    public BasicCache cache() {
        return new CacheImpl(Thread.currentThread().getContextClassLoader().getResource("crowd-ehcache.xml"));
    }
}

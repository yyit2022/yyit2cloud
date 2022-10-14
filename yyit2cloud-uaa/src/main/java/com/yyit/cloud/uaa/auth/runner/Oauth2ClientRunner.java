package com.yyit.cloud.uaa.auth.runner;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.List;

/**
 * 初始化 OAuth2 client
 */
@Component
@RequiredArgsConstructor
public class Oauth2ClientRunner implements ApplicationRunner {

    private final RegisteredClientRepository registeredClientRepository;

    @Override
    public void run(ApplicationArguments args) throws Exception {
        // @formatter:off
        RegisteredClient registeredClient = RegisteredClient.withId("3476adfc-e2bc-4b08-8be8-f2e8a86772f1")
                .clientId("yyit")
                .clientSecret("{noop}yyit")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .scope(OidcScopes.OPENID)
                .scopes(s ->{
                    s.add("message.read");
                    s.add("message.write");
                })
                .redirectUri("https://www.baidu.com")
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(true)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(5))
                        .refreshTokenTimeToLive(Duration.ofDays(1))
                        .build())
                .build();


        // @formatter:on

        registeredClientRepository.save(registeredClient);
    }
}

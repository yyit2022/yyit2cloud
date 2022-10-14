package com.yyit.cloud.uaa.auth.properties;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties(prefix = "yyit2cloud.auth.authorization-server")
public class AuthorizationServerProperties {

    private String issuer;


}

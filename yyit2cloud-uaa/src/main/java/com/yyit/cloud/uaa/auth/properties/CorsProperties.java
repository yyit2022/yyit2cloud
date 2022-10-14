package com.yyit.cloud.uaa.auth.properties;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.PropertyMapper;
import org.springframework.util.CollectionUtils;
import org.springframework.web.cors.CorsConfiguration;

import java.util.ArrayList;
import java.util.List;

/**
 * 跨域属性
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "yyit2cloud.auth.cors")
public class CorsProperties {
    private List<String> allowedOrigins = new ArrayList<>();
    private List<String> allowedOriginPatterns = new ArrayList<>();
    private List<String> allowedMethods = new ArrayList<>();
    private List<String> allowedHeaders = new ArrayList<>();
    private List<String> exposedHeaders = new ArrayList<>();
    private Boolean allowCredentials;
    private Long maxAge;

    public CorsConfiguration toCorsConfiguration() {
        if (CollectionUtils.isEmpty(this.allowedOrigins) && CollectionUtils.isEmpty(this.allowedOriginPatterns)) {
            return null;
        }
        PropertyMapper map = PropertyMapper.get();
        CorsConfiguration config = new CorsConfiguration();
        map.from(this::getAllowedOrigins).to(config::setAllowedOrigins);
        map.from(this::getAllowedOriginPatterns).to(config::setAllowedOriginPatterns);
        map.from(this::getAllowedHeaders).whenNot(CollectionUtils::isEmpty).to(config::setAllowedHeaders);
        map.from(this::getAllowedMethods).whenNot(CollectionUtils::isEmpty).to(config::setAllowedMethods);
        map.from(this::getExposedHeaders).whenNot(CollectionUtils::isEmpty).to(config::setExposedHeaders);
        map.from(this::getMaxAge).whenNonNull().to(config::setMaxAge);
        map.from(this::getAllowCredentials).whenNonNull().to(config::setAllowCredentials);
        return config;
    }
}

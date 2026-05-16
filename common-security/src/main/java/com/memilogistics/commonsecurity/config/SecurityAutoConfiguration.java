package com.memilogistics.commonsecurity.config;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;

@AutoConfiguration
@ComponentScan(basePackages = "com.memilogistics.commonsecurity")
@EnableConfigurationProperties(JwtProperties.class)
public class SecurityAutoConfiguration {

}

package com.bjut.ca.Config;


import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class Knife4jConfig {

    @Bean
    public GroupedOpenApi adminApi() {
        return GroupedOpenApi.builder()
                .group("admin-api")
                .pathsToMatch("/**")
                .build();
    }

    @Bean
    public OpenAPI openAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("Knife4j整合Swagger3 Api接口文档")
                        .description("Knife4j后端接口服务…")
                        .version("v1.0.0")
                        .contact(new Contact().name("yourName").email("yourEmail"))
                        .license(new License().name("Apache 2.0").url("http://springdoc.org")));
    }
}
package com.bjut.blockchain.web.Config;

import org.slf4j.Logger; // 引入SLF4J Logger
import org.slf4j.LoggerFactory; // 引入SLF4J LoggerFactory
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    // 使用SLF4J进行日志记录
    private static final Logger logger = LoggerFactory.getLogger(AuthInterceptor.class);

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                .allowedOrigins("http://localhost:63342", "http://127.0.0.1:63342", "http://localhost:8080") // 确保您的前端源被允许
                .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD")
                .allowedHeaders("*")
                .allowCredentials(true);
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new AuthInterceptor())
                .addPathPatterns("/**") // 拦截所有路径
                .excludePathPatterns( // 以下路径不需要认证即可访问
                        // DID 认证流程API
                        "/api/did/auth/challenge",
                        "/api/did/auth/verify",
                        // DID 管理API
                        "/api/did/create",      // *** FIX: 允许创建DID的API匿名访问 ***
                        "/api/did/resolve/**",  // DID解析通常是公开的
                        "/api/did/logout",      // 登出
                        // 登录页面本身
                        "/login.html",
                        // 主页面本身允许加载，其内部API调用受保护
                        "/BlockChain.html",
                        // Spring Boot 默认错误处理页面
                        "/error",
                        // 静态资源 (确保路径正确，例如 /static/css/** 如果文件在 src/main/resources/static/css下)
                        "/css/**",
                        "/js/**",
                        "/images/**",
                        "/favicon.ico"
                        // 其他明确需要公开的API端点
                        // 例如: "/api/public/**"
                );
    }

    static class AuthInterceptor implements HandlerInterceptor {
        @Override
        public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws IOException {
            String requestUri = request.getRequestURI();
            // 使用 logger.debug 或 logger.trace 记录更详细的请求信息，避免在生产环境中过多INFO日志
            logger.trace("AuthInterceptor: 接收到请求 -> URI: {}, 方法: {}", requestUri, request.getMethod());

            // 对于CORS预检请求 (OPTIONS)，直接放行
            if (HttpMethod.OPTIONS.matches(request.getMethod())) {
                logger.trace("AuthInterceptor: OPTIONS请求，直接放行 URI: {}", requestUri);
                response.setStatus(HttpServletResponse.SC_OK);
                return true;
            }

            HttpSession session = request.getSession(false); // 获取现有会话，如果不存在则不创建

            if (session != null) {
                logger.trace("AuthInterceptor: 找到现有会话 ID: {}", session.getId());
                Object loggedInUser = session.getAttribute("loggedInUserDid");
                if (loggedInUser != null) {
                    logger.trace("AuthInterceptor: 会话已认证，用户DID: '{}'。允许访问 URI: {}", loggedInUser, requestUri);
                    return true; // 用户已登录，允许访问
                } else {
                    logger.warn("AuthInterceptor: 会话存在 (ID: {}) 但未找到 'loggedInUserDid' 属性。视为未认证。 URI: {}", session.getId(), requestUri);
                }
            } else {
                logger.trace("AuthInterceptor: 未找到活动会话。视为未认证。 URI: {}", requestUri);
            }

            // 用户未登录或会话中无有效标记
            // 注意：Spring MVC的路径匹配机制会优先处理 excludePathPatterns。
            // 如果一个路径被排除了，这个 preHandle 方法仍然会针对该路径执行，
            // 但由于Spring已经决定放行，这里的逻辑主要是针对那些*未被排除*且需要认证的路径。
            // 对于已经被Spring排除的路径，此拦截器不应该再将其重定向或返回401。
            // 因此，下面的逻辑主要是在 "双重检查" 或处理那些未被 `excludePathPatterns` 覆盖但又需要特殊处理的场景。
            // 但通常，依赖 `excludePathPatterns` 是主要机制。

            // 如果请求是API请求 (通常以 /api/ 开头) 且未被排除
            if (requestUri.startsWith("/api/")) {
                // 此处我们假设 excludePathPatterns 已经正确处理了所有应该被排除的API。
                // 如果代码执行到这里，意味着这是一个 *未被排除* 的API请求，而用户又未认证。
                logger.warn("AuthInterceptor: 拦截到未授权的API请求 URI: {}。返回401。", requestUri);
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setContentType("application/json");
                response.setCharacterEncoding("UTF-8");
                // 返回更简洁的错误信息给客户端
                response.getWriter().write("{\"success\": false, \"message\": \"访问未授权 (401)，请先登录或提供有效凭证。\"}");
                return false; // 阻止未授权的API请求
            }

            // 对于非API的、受保护的页面请求（即不在排除列表中的HTML页面）
            logger.info("AuthInterceptor: 非API请求 URI: {}，且用户未认证。重定向到登录页面。", requestUri);
            response.sendRedirect(request.getContextPath() + "/login.html"); // 确保getContextPath()是正确的
            return false; // 阻止请求并重定向
        }
    }
}

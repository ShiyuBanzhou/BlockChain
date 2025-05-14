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
                .allowedOrigins("http://localhost:63342", "http://127.0.0.1:63342", "http://localhost:8080")
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
                        // DID 管理API (创建和解析通常需要根据实际需求决定是否公开)
                        // "/api/did/create", // 如果创建DID需要认证，则不应排除
                        // "/api/did/resolve/**", // DID解析通常是公开的
                        "/api/did/logout",      // 登出
                        // 登录页面本身
                        "/login.html",
                        // 主页面本身允许加载，其内部API调用受保护
                        "/BlockChain.html",
                        // Spring Boot 默认错误处理页面
                        "/error",
                        // 静态资源
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
            logger.info("AuthInterceptor: 接收到请求 -> URI: {}, 方法: {}", requestUri, request.getMethod());

            // 对于CORS预检请求 (OPTIONS)，直接放行
            if (HttpMethod.OPTIONS.matches(request.getMethod())) {
                logger.info("AuthInterceptor: OPTIONS请求，直接放行 URI: {}", requestUri);
                response.setStatus(HttpServletResponse.SC_OK);
                return true;
            }

            HttpSession session = request.getSession(false); // 获取现有会话，如果不存在则不创建

            if (session != null) {
                logger.info("AuthInterceptor: 找到现有会话 ID: {}", session.getId());
                Object loggedInUser = session.getAttribute("loggedInUserDid");
                if (loggedInUser != null) {
                    logger.info("AuthInterceptor: 会话已认证，用户DID: '{}'。允许访问 URI: {}", loggedInUser, requestUri);
                    return true; // 用户已登录，允许访问
                } else {
                    logger.warn("AuthInterceptor: 会话存在 (ID: {}) 但未找到 'loggedInUserDid' 属性。视为未认证。 URI: {}", session.getId(), requestUri);
                }
            } else {
                logger.info("AuthInterceptor: 未找到活动会话。视为未认证。 URI: {}", requestUri);
            }

            // 用户未登录或会话中无有效标记
            logger.warn("AuthInterceptor: 未授权访问尝试。 URI: {}", requestUri);

            // 对于API请求 (所有受保护的API都应该以 /api/ 开头，并且不在排除列表中)
            // 注意：Spring MVC的路径匹配机制会处理 excludePathPatterns，
            // 所以如果一个API路径被排除了，拦截器逻辑到这里时，它仍然会执行，但我们通常依赖于Spring的排除。
            // 这里的检查是双重保险，并确保对未排除的API进行正确处理。
            if (requestUri.startsWith("/api/")) {
                // 检查此API路径是否明确在排除列表中（虽然Spring应该已经处理了，但可以加一道保险）
                // 这个检查逻辑可以更复杂，但核心是如果它是一个应该被保护的API，则返回401
                boolean isExcludedApi = requestUri.equals("/api/did/auth/challenge") ||
                        requestUri.equals("/api/did/auth/verify") ||
                        requestUri.equals("/api/did/logout");
                // 您可能还需要排除 /api/did/create 如果它不需要登录

                if (isExcludedApi) {
                    logger.info("AuthInterceptor: API URI '{}' 在排除列表中，允许匿名访问。", requestUri);
                    return true; // 允许访问已排除的API
                } else {
                    logger.warn("AuthInterceptor: 拦截到未授权的API请求 URI: {}。返回401。", requestUri);
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.setContentType("application/json");
                    response.setCharacterEncoding("UTF-8");
                    response.getWriter().write("{\"success\": false, \"message\": \"访问未授权 (401)，请先登录或提供有效凭证。API: " + requestUri + "\"}");
                    return false; // 阻止未授权的API请求
                }
            }

            // 对于非API的、受保护的页面请求（即不在排除列表中的HTML页面）
            // BlockChain.html 已在排除列表中，所以它不会走到这里被重定向。
            // login.html 也在排除列表中。
            // 如果有其他如 /admin/dashboard.html 这样的页面且未排除，则会被重定向。
            logger.info("AuthInterceptor: 非API请求 URI: {}，且用户未认证。重定向到登录页面。", requestUri);
            response.sendRedirect(request.getContextPath() + "/login.html");
            return false; // 阻止请求并重定向
        }
    }
}
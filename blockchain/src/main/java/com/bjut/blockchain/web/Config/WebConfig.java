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
                .allowedOrigins("http://localhost:63342", "http://127.0.0.1:63342", "http://localhost:8080", "http://localhost:8090") // 添加可能的后端端口8090
                .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD")
                .allowedHeaders("*")
                .allowCredentials(true)
                .maxAge(3600);
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new AuthInterceptor())
                .addPathPatterns("/**") // 拦截所有路径
                .excludePathPatterns( // 以下路径不需要认证即可访问
                        // DID 认证流程API
                        "/api/did/auth/challenge",
                        "/api/did/auth/verify",
                        // 新增：会话状态验证API
                        "/api/did/auth/session-status",
                        // 新增：匿名认证流程API
                        "/api/did/auth/anonymous-challenge", // <--- 新增排除
                        "/api/did/auth/anonymous-verify",   // <--- 新增排除
                        // DID 管理API
                        "/api/did/create",      // 允许创建DID的API匿名访问
                        "/api/did/resolve/**",  // DID解析通常是公开的
                        "/api/did/list",        // 列出所有DID通常也是公开的或有特定权限
                        "/api/did/logout",      // 登出
                        // 登录页面本身
                        "/login.html",
                        // 主页面本身允许加载，其内部API调用受保护
                        "/BlockChain.html",
                        // CA相关公开接口
                        "/api/ca/root-certificate", // 获取根证书通常是公开的
                        "/api/ca/crl",              // 获取CRL通常是公开的
                        // 文件下载接口
                        "/api/downloads/client-zip",
                        // Spring Boot 默认错误处理页面
                        "/error",
                        // 静态资源 (确保路径正确)
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
            logger.trace("AuthInterceptor: 接收到请求 -> URI: {}, 方法: {}", requestUri, request.getMethod());

            // 对于CORS预检请求 (OPTIONS)，直接放行
            if (HttpMethod.OPTIONS.matches(request.getMethod())) {
                logger.trace("AuthInterceptor: OPTIONS请求，直接放行 URI: {}", requestUri);
                response.setStatus(HttpServletResponse.SC_OK);
                return true;
            }
            
            // 新增：检查HTTP请求头中的认证信息
            String authToken = request.getHeader("X-Auth-Token");
            String authSession = request.getHeader("X-Auth-Session");
            String authDid = request.getHeader("X-Auth-DID");
            
            if (authToken != null && !authToken.isEmpty()) {
                logger.trace("AuthInterceptor: 请求中包含Auth-Token: {}, DID: {}", authToken, authDid);
                // 简单验证，实际应用中可能需要更复杂的令牌验证逻辑
                if (("authenticated".equals(authToken) || "anonymous_authenticated".equals(authToken)) && 
                    authSession != null && !authSession.isEmpty()) {
                    // 在会话中设置认证标记
                    HttpSession session = request.getSession(true);
                    if (authDid != null && !authDid.isEmpty()) {
                        // DID认证
                        session.setAttribute("loggedInUserDid", authDid);
                        logger.trace("AuthInterceptor: 从请求头设置DID认证 - DID: {}", authDid);
                    } else {
                        // 匿名认证
                        session.setAttribute("anonymouslyLoggedIn", true);
                        logger.trace("AuthInterceptor: 从请求头设置匿名认证");
                    }
                    return true;
                }
            }

            HttpSession session = request.getSession(false); // 获取现有会话，如果不存在则不创建

            if (session != null) {
                logger.trace("AuthInterceptor: 找到现有会话 ID: {}", session.getId());
                Object loggedInUserDid = session.getAttribute("loggedInUserDid");
                if (loggedInUserDid != null) {
                    logger.trace("AuthInterceptor: 会话已通过DID认证，用户DID: '{}'。允许访问 URI: {}", loggedInUserDid, requestUri);
                    return true; // 用户已通过DID登录，允许访问
                }

                // 新增：检查匿名认证状态
                Object anonymouslyLoggedIn = session.getAttribute("anonymouslyLoggedIn");
                if (anonymouslyLoggedIn != null && (Boolean) anonymouslyLoggedIn) {
                    logger.trace("AuthInterceptor: 会话已通过匿名认证。URI: {}", requestUri);
                    // 在这里，您可以根据 requestUri 进一步控制匿名用户可以访问哪些受保护的资源。
                    // 例如，如果匿名用户只能访问特定的API子集：
                    // if (requestUri.startsWith("/api/some-anonymous-allowed-action")) {
                    //     return true;
                    // } else if (requestUri.startsWith("/api/")) { // 其他API则禁止
                    //     logger.warn("AuthInterceptor: 匿名认证用户尝试访问受限API URI: {}。返回403 Forbidden。", requestUri);
                    //     response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                    //     response.setContentType("application/json");
                    //     response.setCharacterEncoding("UTF-8");
                    //     response.getWriter().write("{\"success\": false, \"message\": \"匿名访问权限不足 (403)。\"}");
                    //     return false;
                    // }
                    // 为了简单起见，当前我们假设如果 "anonymouslyLoggedIn" 为 true，则允许访问那些未被排除且需要某种形式认证的路径。
                    // 具体的权限控制需要根据您的业务需求来细化。
                    return true; // 允许匿名认证用户继续访问（后续可能还有其他权限检查）
                }

                logger.trace("AuthInterceptor: 会话存在 (ID: {}) 但未找到 'loggedInUserDid' 或 'anonymouslyLoggedIn' 属性。视为未认证。 URI: {}", session.getId(), requestUri);

            } else {
                logger.trace("AuthInterceptor: 未找到活动会话。视为未认证。 URI: {}", requestUri);
            }

            // 用户未登录（既没有DID登录也没有匿名登录）
            // excludePathPatterns 已经处理了所有明确允许匿名访问的路径。
            // 如果请求到达这里，意味着它是一个需要认证的路径，但用户未认证。

            if (requestUri.startsWith("/api/")) {
                // 对于需要认证但未认证的API请求
                logger.warn("AuthInterceptor: 拦截到未授权的API请求 URI: {}。返回401 Unauthorized。", requestUri);
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setContentType("application/json");
                response.setCharacterEncoding("UTF-8");
                response.getWriter().write("{\"success\": false, \"message\": \"访问未授权 (401)，请先登录或进行认证。\"}");
                return false;
            }

            // 对于需要认证但未认证的页面请求（非API，且不在排除列表中的HTML页面）
            // 例如，如果 BlockChain.html 页面本身不应该在未登录时直接访问其内容（即使页面框架加载了）
            // 但我们已将 BlockChain.html 加入排除列表，所以这里的逻辑更多是针对其他可能存在的受保护页面。
            logger.info("AuthInterceptor: 受保护的页面请求 URI: {}，且用户未认证。重定向到登录页面 /login.html。", requestUri);
            response.sendRedirect(request.getContextPath() + "/login.html");
            return false;
        }
    }
}

package com.bjut.blockchain.web.Config;

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

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**") // 允许所有路径
                // 允许来自这些源的跨域请求 (根据您的前端开发和部署环境调整)
                .allowedOrigins("http://localhost:63342", "http://127.0.0.1:63342", "http://localhost:8080")
                .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD") // 允许的HTTP方法
                .allowedHeaders("*") // 允许所有请求头
                .allowCredentials(true); // 允许发送凭据 (例如cookies, authorization headers)
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new AuthInterceptor())
                .addPathPatterns("/**") // 拦截所有路径
                .excludePathPatterns( // 以下路径不需要认证即可访问
                        // DID 挑战-响应认证流程自身相关的路径
                        "/api/did/auth/challenge",
                        "/api/did/auth/verify",
                        "/api/did/auth/sign-challenge-for-demo", // 仅供演示的签名辅助接口

                        // DID 创建和解析通常是公开的或有特定访问控制（非会话认证）
                        "/api/did/create",      // 创建DID的接口
                        "/api/did/resolve/**",  // 解析DID文档的接口

                        // 用户登出接口也应该能被（至少是尝试）未认证用户访问以清除可能存在的状态
                        "/api/did/logout",      // 用户登出

                        // 前端页面本身
                        "/login.html",          // 登录页面
                        "/BlockChain.html",     // 主操作页面 (其内部的API调用仍会受拦截器保护)

                        // Spring Boot 默认的错误处理路径
                        "/error",

                        // 静态资源 (CSS, JavaScript, 图片等)
                        "/css/**",
                        "/js/**",
                        "/images/**",
                        "/favicon.ico"

                        // 其他需要公开访问的API端点
                        // 例如: "/api/public/**", "/api/health-check"
                );
    }

    // 认证拦截器实现
    static class AuthInterceptor implements HandlerInterceptor {
        @Override
        public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws IOException {
            // 对于 CORS 预检请求 (OPTIONS)，直接放行，因为它们不携带凭证且用于探测服务器能力
            if (HttpMethod.OPTIONS.matches(request.getMethod())) {
                response.setStatus(HttpServletResponse.SC_OK);
                return true;
            }

            HttpSession session = request.getSession(false); // 获取现有会话，如果不存在则不创建

            // 检查会话中是否有已登录用户的标记
            if (session != null && session.getAttribute("loggedInUserDid") != null) {
                // 用户已登录，允许访问
                System.out.println("拦截器：会话已认证，用户DID: " + session.getAttribute("loggedInUserDid") + "，请求 URI: " + request.getRequestURI());
                return true;
            }

            // 用户未登录或会话中无标记
            String requestUri = request.getRequestURI();
            System.out.println("拦截器：未授权访问尝试 -> URI: " + requestUri + " | 方法: " + request.getMethod() + " | 来源IP: " + request.getRemoteAddr() + (session == null ? " (无会话)" : " (会话ID: " + session.getId() + ")"));

            // 对于 API 请求 (所有受保护的 API 都应该以 /api/ 开头，且未在 excludePathPatterns 中排除)
            if (requestUri.startsWith("/api/")) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED); // 401 未授权
                response.setContentType("application/json");
                response.setCharacterEncoding("UTF-8");
                // 返回统一的JSON错误格式
                response.getWriter().write("{\"success\": false, \"message\": \"访问未授权，请先登录或提供有效凭证 (来自拦截器)。\"}");
                return false; // 阻止请求继续执行
            }

            // 对于非API的受保护页面请求 (如果除了 login.html 外还有其他受保护的HTML页面)
            // 这里假设除了 login.html 和静态资源外，其他HTML页面都需要登录
            // 这个逻辑可能需要根据您的具体页面结构调整
            if (requestUri.endsWith(".html") && !requestUri.endsWith("login.html")) {
                System.out.println("拦截器：访问受保护页面 " + requestUri + "，重定向到登录页。");
                response.sendRedirect(request.getContextPath() + "/login.html");
                return false;
            }

            // 对于其他未明确处理的请求（例如访问 login.html 自身，或已被排除的路径），默认允许通过
            // 注意：这个拦截器主要关注API和特定页面的保护。静态资源已通过excludePathPatterns排除。
            return true;
        }
    }
}
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
                        "/api/did/login",       // <--- 修改: 确保登录API被正确排除
                        "/api/did/logout",      // <--- 修改: 确保登出API被正确排除
                        // 如果有注册接口，也应排除，例如: "/api/did/register"
                        "/login.html",          // 登录页面本身
                        "/BlockChain.html",     // 主页面本身允许访问，其内部API调用受保护
                        "/error",               // Spring Boot 默认错误处理页面
                        // 静态资源
                        "/css/**",
                        "/js/**",
                        "/images/**",
                        "/favicon.ico"
                        // 如果有其他公共API（例如获取版本信息，健康检查等），也应在此处排除
                        // 例如: "/api/public/**"
                );
    }

    static class AuthInterceptor implements HandlerInterceptor {
        @Override
        public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws IOException {
            // 对于CORS预检请求 (OPTIONS)，直接放行
            if (HttpMethod.OPTIONS.matches(request.getMethod())) {
                response.setStatus(HttpServletResponse.SC_OK);
                return true;
            }

            HttpSession session = request.getSession(false);

            // 检查会话中是否有登录标记
            if (session != null && session.getAttribute("loggedInUserDid") != null) {
                // System.out.println("会话已认证: " + session.getId() + " 用户: " + session.getAttribute("loggedInUserDid"));
                return true; // 用户已登录，允许访问
            }

            // 用户未登录或会话中无标记
            String requestUri = request.getRequestURI();
            System.out.println("未授权访问尝试 (拦截器): " + requestUri + " | 方法: " + request.getMethod() + " | 请求来源IP: " + request.getRemoteAddr() + (session == null ? " (无会话)" : " (会话ID: " + session.getId() + ")"));

            // 对于API请求 (现在所有受保护的API都应该以 /api/ 开头)
            if (requestUri.startsWith("/api/")) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setContentType("application/json");
                response.setCharacterEncoding("UTF-8");
                response.getWriter().write("{\"success\": false, \"message\": \"访问未授权，请先登录或提供有效凭证 (来自拦截器)。\"}");
                return false;
            }

            // 对于非API的受保护页面请求, 重定向到登录页
            response.sendRedirect(request.getContextPath() + "/login.html");
            return false;
        }
    }
}

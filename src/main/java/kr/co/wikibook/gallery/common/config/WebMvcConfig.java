package kr.co.wikibook.gallery.common.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
//@RequiredArgsConstructor
public class WebMvcConfig implements WebMvcConfigurer {

//    private final ApiInterceptor apiInterceptor;

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                .allowedOrigins("http://localhost:5173")
                .allowedMethods("*")
                .allowCredentials(true);
    }

//    @Override
//    public void addInterceptors(InterceptorRegistry registry) {
//        registry.addInterceptor(apiInterceptor)
//                .addPathPatterns("/v1/api/**")
//                .excludePathPatterns("/v1/api/account/**", "/v1/api/items/**"); // 예외
//    }
}
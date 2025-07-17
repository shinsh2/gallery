package kr.co.wikibook.gallery.common.config.authenticate;

import java.io.IOException;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import kr.co.wikibook.gallery.common.util.ApiResult;
import kr.co.wikibook.gallery.common.util.JsonUtils;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class SimpleAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
	private final SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();
	
	private final SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();
		

  @Override
  public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                      Authentication authentication) throws IOException {
	log.debug("Authentication successful for user: {}", authentication.getName());

	SecurityContext securityContext = this.securityContextHolderStrategy.getContext();
	securityContext.setAuthentication(authentication);
	this.securityContextRepository.saveContext(securityContext, request, response);
		
    response.setStatus(HttpStatus.OK.value());
    JsonUtils.write(response.getWriter(), ApiResult.message("authenticated"));
  }
}

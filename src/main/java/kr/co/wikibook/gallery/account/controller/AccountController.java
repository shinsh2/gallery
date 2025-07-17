package kr.co.wikibook.gallery.account.controller;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;
import kr.co.wikibook.gallery.account.dto.AccountJoinRequest;
import kr.co.wikibook.gallery.account.etc.AccountConstants;
import kr.co.wikibook.gallery.account.helper.AccountHelper;
import kr.co.wikibook.gallery.block.service.BlockService;
import kr.co.wikibook.gallery.common.config.CustomUserDetails;
import kr.co.wikibook.gallery.common.util.HttpUtils;
import kr.co.wikibook.gallery.common.util.JwtUtils;
import kr.co.wikibook.gallery.member.service.MemberService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/v1")
public class AccountController {

    private final AccountHelper accountHelper;
    private final BlockService blockService;
    private final MemberService memberService;

    @PostMapping("/api/account/join")
    public ResponseEntity<?> join(@RequestBody AccountJoinRequest joinReq) {
    	log.debug(joinReq.toString());
    	
        // 입력 값이 비어 있다면
        if (!StringUtils.hasLength(joinReq.getName()) || !StringUtils.hasLength(joinReq.getLoginId()) || !StringUtils.hasLength(joinReq.getLoginPw())) {
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }

        // 중복 로그인 아이디가 있으면
        if (memberService.find(joinReq.getLoginId()) != null) { // ③
            return new ResponseEntity<>(HttpStatus.CONFLICT);
        }

        accountHelper.join(joinReq);
        return new ResponseEntity<>(HttpStatus.OK);
    }

//    @PostMapping("/api/account/login")
//    public ResponseEntity<?> login(HttpServletRequest req, HttpServletResponse res, @RequestBody AccountLoginRequest loginReq) {
//        // 입력 값이 비어 있다면
//        if (!StringUtils.hasLength(loginReq.getUsername()) || !StringUtils.hasLength(loginReq.getPassword())) {
//            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
//        }
//
//        String output = accountHelper.login(loginReq, req, res);
//
//        if (output == null) { // 로그인 실패 시
//            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
//        }
//
//        return new ResponseEntity<>(output, HttpStatus.OK);
//    }

    @GetMapping("/api/account/check")
    public ResponseEntity<?> check(HttpServletRequest req) {
        return new ResponseEntity<>(isAuthenticated(), HttpStatus.OK);
//        return new ResponseEntity<>(accountHelper.isLoggedIn(req), HttpStatus.OK);
    }

    private boolean isAuthenticated() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        log.debug(authentication != null ? authentication.toString() : "No authentication found");
        if (authentication == null || authentication instanceof AnonymousAuthenticationToken) {
            return false;
        }
        return authentication.isAuthenticated();
    }
    
    //    @PostMapping("/api/account/logout")
//    public ResponseEntity<?> logout(HttpServletRequest req, HttpServletResponse res) {
//        accountHelper.logout(req, res);
//        return new ResponseEntity<>(HttpStatus.OK);
//    }

    @GetMapping("/api/account/token")
    public ResponseEntity<?> regenerate(HttpServletRequest req) {
        String accessToken = "";
        String refreshToken = HttpUtils.getCookieValue(req, AccountConstants.REFRESH_TOKEN_NAME);

        // 리프레시 토큰이 유효하다면
        if (StringUtils.hasLength(refreshToken) && JwtUtils.isValid(refreshToken) && !blockService.has(refreshToken)) {
            // 리프레시 토큰의 내부 값 조회
            Map<String, Object> tokenBody = JwtUtils.getBody(refreshToken);

            // 리프레시 토큰의 회원 아이디 조회
            Integer memberId = (Integer) tokenBody.get(AccountConstants.MEMBER_ID_NAME);

            // 액세스 토큰 발급
            accessToken = JwtUtils.generate(AccountConstants.ACCESS_TOKEN_NAME, AccountConstants.MEMBER_ID_NAME, memberId, AccountConstants.ACCESS_TOKEN_EXP_MINUTES);
        }

        return new ResponseEntity<>(accessToken, HttpStatus.OK);
    }
}
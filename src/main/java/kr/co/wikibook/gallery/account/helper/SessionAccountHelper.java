package kr.co.wikibook.gallery.account.helper;

import org.springframework.context.annotation.Primary;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import kr.co.wikibook.gallery.account.dto.AccountJoinRequest;
import kr.co.wikibook.gallery.account.dto.AccountLoginRequest;
import kr.co.wikibook.gallery.account.etc.AccountConstants;
import kr.co.wikibook.gallery.common.config.CustomUserDetails;
import kr.co.wikibook.gallery.common.util.HttpUtils;
import kr.co.wikibook.gallery.member.entity.Member;
import kr.co.wikibook.gallery.member.service.MemberService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@Primary
@RequiredArgsConstructor
public class SessionAccountHelper implements AccountHelper {

    private final MemberService memberService;

    // 회원가입
    @Override
    public void join(AccountJoinRequest joinReq) {
        memberService.save(joinReq.getName(), joinReq.getLoginId(), joinReq.getLoginPw());
    }

    // 로그인
    @Override
    public String login(AccountLoginRequest loginReq, HttpServletRequest req, HttpServletResponse res) {
        Member member = memberService.find(loginReq.getUsername(), loginReq.getPassword());

        // 회원 데이터가 없으면
        if (member == null) {
            return null;
        }

        HttpUtils.setSession(req, AccountConstants.MEMBER_ID_NAME, member.getId());
        return member.getLoginId();
    }

    // 회원 아이디 조회
    @Override
    public Integer getMemberId(HttpServletRequest req) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        CustomUserDetails customUserDetails = (CustomUserDetails) authentication.getPrincipal();
        log.debug(customUserDetails.toString());
        return customUserDetails.getId();
//        Object memberId = HttpUtils.getSessionValue(req, AccountConstants.MEMBER_ID_NAME);
//
//        if (memberId != null) {
//            return (int) memberId;
//        }
//
//        return null;
    }

    // 로그인 여부 확인
    @Override
    public boolean isLoggedIn(HttpServletRequest req) {
        return getMemberId(req) != null;
    }

    // 로그아웃
    @Override
    public void logout(HttpServletRequest req, HttpServletResponse res) {
        HttpUtils.removeSession(req, AccountConstants.MEMBER_ID_NAME);
    }
}
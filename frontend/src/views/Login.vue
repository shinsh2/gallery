<script setup>
import { reactive } from "vue";
import { login } from "@/services/accountService";
import { useRouter } from "vue-router";
import { useAccountStore } from "@/stores/account";

// function getCookie(name) {
//   let cookieValue = null;
//   if (document.cookie && document.cookie !== '') {
//     const cookies = document.cookie.split(';');
//     for (let i = 0; i < cookies.length; i++) {
//       const cookie = cookies[i].trim();
//       if (cookie.substring(0, name.length + 1) === (name + '=')) {
//         cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
//         break;
//       }
//     }
//   }
//   return cookieValue;
// }

// 반응형 상태
const state = reactive({
  form: {
    username: "",
    password: "",
  }
});

// 라우터 객체
const router = useRouter();

// 계정 스토어
const accountStore = useAccountStore();

// 로그인 데이터 제출
const submit = async () => {
  if (!state.form.username?.trim()) {
    window.alert("이메일을 입력해주세요.");
    document.getElementById("username")?.focus();
    return;
  } else if (!state.form.password?.trim()) {
    window.alert("패스워드를 입력해주세요.");
    document.getElementById("password")?.focus();
    return;
  }

  // const csrfToken = getCookie('XSRF-TOKEN');
  // console.log("CSRF Token:", csrfToken);
  // const headers = {
  //   'X-XSRF-TOKEN': csrfToken,
  //   'Content-Type': 'application/json' // 또는 다른 Content-Type
  // };
  // const res = await login(state.form, { headers });
  const res = await login(state.form);

  switch (res.status) {
    case 200:
      accountStore.setAccessToken(res.data);
      await router.push("/");
      break;

    case 404:
      window.alert("입력하신 정보와 일치하는 회원이 없습니다.")
      break;
  }
};
</script>

<template>
  <div class="login">
    <div class="container">
      <form class="py-5 d-flex flex-column gap-3" @submit.prevent="submit">
        <h1 class="h5 mb-3">로그인</h1>
        <div class="form-floating">
          <input type="email" class="form-control" id="username" placeholder="이메일" v-model="state.form.username">
          <label for="username">이메일</label>
        </div>
        <div class="form-floating">
          <input type="password" class="form-control" id="password" placeholder="패스워드" v-model="state.form.password">
          <label for="password">패스워드</label>
        </div>
        <button type="submit" class="w-100 h6 btn py-3 btn-primary">로그인</button>
      </form>
    </div>
  </div>
</template>

<style lang="scss" scoped>
.login>.container {
  max-width: 576px;
}
</style>
<script setup lang="ts">
</script>

<template>
  <div>
    <el-card>
      <template #header>
        <span>首页</span>
      </template>
      <p>SSO SDK Demo 系统</p>
      <el-button type="primary" @click="$router.push('/items')">
        查看 Items
      </el-button>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { itemApi, type Item } from '../api'

const items = ref<Item[]>([])
const loading = ref(false)

const fetchItems = async () => {
  loading.value = true
  try {
    const { data } = await itemApi.list()
    items.value = data.data
  } finally {
    loading.value = false
  }
}

onMounted(fetchItems)
</script>

<template>
  <div>
    <el-card>
      <template #header>
        <div style="display: flex; justify-content: space-between; align-items: center">
          <span>Items 列表</span>
          <el-button type="primary" size="small" @click="$router.push('/')">
            返回首页
          </el-button>
        </div>
      </template>
      <el-table :data="items" v-loading="loading" stripe>
        <el-table-column prop="id" label="ID" width="80" />
        <el-table-column prop="name" label="Name" />
      </el-table>
    </el-card>
  </div>
</template>

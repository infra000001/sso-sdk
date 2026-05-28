import axios from 'axios'

const http = axios.create({
  baseURL: '/api/v1',
  timeout: 5000
})

export interface Item {
  id: number
  name: string
}

export interface Response<T> {
  code: number
  msg: string
  data: T
}

export const itemApi = {
  list: () => http.get<Response<Item[]>>('/items'),
  get: (id: number) => http.get<Response<Item>>(`/items/${id}`)
}

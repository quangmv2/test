import { IResponseErrorParams } from '@constants/interface'
import { notification } from 'antd'
import axios, { AxiosError } from 'axios'
import { ACCESS_TOKEN, PAGES, REFRESH_TOKEN } from '../constants'

const isServer = () => {
    return typeof window === 'undefined'
}

let accessToken = ''
const baseURL = process.env.REACT_APP_BACKEND_URL!

export const setAccessToken = (_accessToken: string) => {
    accessToken = _accessToken
}

export const getAccessToken = () => accessToken

export const api = axios.create({
    baseURL,
    headers: {
        'Content-Type': 'application/json',
        'Access-Control-Expose-Headers':
            'Content-Disposition,X-Suggested-Filename',
    },
    withCredentials: true, // to send cookie
})

api.interceptors.request.use((config: any) => {
    const newAccessToken = accessToken || localStorage.getItem(ACCESS_TOKEN)
    if (newAccessToken) {
        config.headers.Authorization = `Bearer ${newAccessToken}`
    }
    return config
})

api.interceptors.response.use(
    (response: any) => {
        return response
    },
    (error: AxiosError<IResponseErrorParams>) => {
        // check conditions to refresh token
        const errorResponse = error.response?.data
        if (errorResponse?.statusCode === 403) {
            notification.error({
                message: 'Permission denied.',
                key: 'permission_denied',
            })
            window.location.href = PAGES.VIEW_PROFILE
            return Promise.reject(error)
        }
        if (
            error.response?.status === 401 &&
            !error.response?.config?.url?.includes('auth/refreshToken') &&
            !error.response?.config?.url?.includes('signin') &&
            (error?.response?.data?.response?.message ===
                'Error validating access token' ||
                error?.response?.data?.response?.message === 'Unauthorized') &&
            !isServer()
        ) {
            localStorage.removeItem(ACCESS_TOKEN)
            return refreshToken(error)
        }
        return Promise.reject(error)
    },
)

let fetchingToken = false
let subscribers: ((token: string) => any)[] = []

const onAccessTokenFetched = (token: string) => {
    subscribers.forEach((callback) => callback(token))
    subscribers = []
}

const addSubscriber = (callback: (token: string) => any) => {
    subscribers.push(callback)
}

const refreshToken = async (oError: AxiosError) => {
    try {
        const { response }: any = oError

        // create new Promise to retry original request
        const retryOriginalRequest = new Promise((resolve) => {
            addSubscriber((token: string) => {
                response!.config.headers['Authorization'] = `Bearer ${token}`
                resolve(axios(response!.config))
            })
        })

        // check whether refreshing token or not
        if (!fetchingToken) {
            fetchingToken = true
            const refreshToken = localStorage.getItem(REFRESH_TOKEN)
            // refresh token
            const { data } = await api.post('/auth/refresh-token', {
                refresh_token: refreshToken,
            })
            // check if this is server or not. We don't wanna save response token on server.
            if (!isServer()) {
                setAccessToken(data.access_token)
                localStorage.setItem(REFRESH_TOKEN, data.refresh_token)
                localStorage.setItem(ACCESS_TOKEN, data.access_token)
            }
            // when new token arrives, retry old requests
            onAccessTokenFetched(data.access_token)
        }
        return retryOriginalRequest
    } catch (error) {
        // on error go to login page
        // if (!isServer() && !Router.asPath.includes('/login')) {
        //     Router.push('/login');
        // }
        if (isServer()) {
            // context.res.setHeader('location', '/sign-in');
            // context.res.statusCode = 302;
            // context.res.end();
        }
        window.location.href = PAGES.SIGN_IN
        return Promise.reject(oError)
    } finally {
        fetchingToken = false
    }
}

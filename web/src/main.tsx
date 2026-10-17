import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { ConfigProvider } from 'antd'
import zhCN from 'antd/locale/zh_CN'
import App from './App'
import './styles.css'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <ConfigProvider
      locale={zhCN}
      theme={{
        token: {
          colorPrimary: '#3d5ce0',
          colorInfo: '#3d5ce0',
          colorSuccess: '#28724c',
          colorWarning: '#96610d',
          colorError: '#bd3340',
          colorText: '#202936',
          colorTextSecondary: '#687486',
          colorBorder: '#e3e7ed',
          colorBgLayout: '#f8f9fb',
          borderRadius: 5,
          controlHeight: 30,
          fontSize: 13,
          fontFamily:
            '-apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif',
        },
        components: {
          Layout: { bodyBg: '#f8f9fb', siderBg: '#ffffff', headerBg: '#ffffff' },
          Table: { headerBg: '#f4f6f9', cellPaddingBlockSM: 6, cellPaddingInlineSM: 10, rowHoverBg: '#f6f8ff' },
          Drawer: { footerPaddingBlock: 12 },
          Form: { itemMarginBottom: 16, verticalLabelPadding: '0 0 6px' },
          Tabs: { horizontalMargin: '0 0 10px 0', horizontalItemPaddingSM: '8px 0' },
        },
      }}
    >
      <App />
    </ConfigProvider>
  </StrictMode>,
)
